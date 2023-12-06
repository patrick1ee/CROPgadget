//compile with
// gcc -fPIC -shared -o monitor.so monitor.c

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

int monitor(long data_address) {
    printf("%lx\n", data_address);
    
    pid_t child_pid, wpid;

    child_pid = fork();
    printf("child pid: %d\n", child_pid);

    if (child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (child_pid == 0) {
        // Child process

        // Allow tracing of this process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }

        execl("/vagrant/vuln3-32", "vuln3-32", "input", NULL);

        // This part is only reached if execl fails
        perror("execl");
        exit(EXIT_FAILURE);
    } else {
        // Parent process

        int status;
        struct user_regs_struct regs;

        // Wait for the child to stop
        wpid = waitpid(child_pid, &status, 0);

        //Set a breakpoint at the specified memory address
        if (ptrace(PTRACE_POKEDATA, child_pid, (void *)data_address, 0xcc) == -1) {
            perror("ptrace poke");
            exit(EXIT_FAILURE);
        }

        int correct = 0;

        // Continue the child process
        ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
        // Main loop to monitor the memory address
        int c = 0;
        while (1) {
            // Wait for the child to stop
            waitpid(child_pid, &status, 0);
            //printf("%d\n", WIFEXITED(status));

            // Check if the child has exited
            if (WIFEXITED(status)) {
                printf("Child process exited.\n");
                break;
            }

            // Get the registers of the child process
            if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
                perror("ptrace getregs");
                exit(EXIT_FAILURE);
            }

            // Check if the program counter is at the breakpoint
            printf("rip: %llx ", regs.rip);
            printf("rsp: %llx ", regs.rsp);
            printf("rdi: %llx ", regs.rdi);
            printf("rsi: %llx ", regs.rsi);
            printf("rbp: %llx ", regs.rbp);

            long rbp_value = ptrace(PTRACE_PEEKDATA, child_pid, (void *)regs.rbp, NULL);
            printf("rbp_value: %lx ", rbp_value);

            if (regs.rbp == 0xffffd268) {
                correct =  1;
            }
            printf("address: %lx\n", data_address);
            if (regs.rip - 2 == data_address) {
                printf("breakpoint:\n");
                unsigned long long sp = regs.rbp;

                int address;
                int ebp_value;
                asm("movl %%ebp, %0" : "=r"(address));
                asm("movl (%0), %1" : : "r"(address), "r"(ebp_value));
                printf("Value at ebp: %d: %p\n", ebp_value, address);

                for (int i =0; i < 4; i++){
                // Read the data at the specified memory address
                long data = ptrace(PTRACE_PEEKDATA, child_pid, 0xffffd268, NULL);

                // Print the monitored data
                printf("Data at 0x%llx: %lx\n", sp, data);
                sp += 16;
                }
                break;

                // Clear the breakpoint and continue
                ptrace(PTRACE_POKEDATA, child_pid, (void *)data_address, 0);
                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            } else {
                // Continue the child process if the program counter is not at the breakpoint
                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            }

            if (c > 100000) break;
            if (regs.rip == 0x80488da) break;
            c++;
        }
        if (correct){
            printf("was at correct address\n");
        } else {
            printf("didnt hit correct address\n");
        }
    }

    return 0;
}

//x/4wx $ebp