#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

void runProgram(const char *programPath) {
    pid_t pid, wpid;
    int status;
    int runs = 0;
    int loop = 1;

    // FILE *fp;

    int bufferlength = 32;
    int dif = 32;
    int previous = 0;

    while (loop) {
        // fp = fopen("input", "w");
        // if(fp!=NULL) {
        //     for (int i = 0; i < bufferlength; i++) {
            
        //     }
        // }

        char *input = malloc(bufferlength + 1);
        memset(input, 'A', bufferlength);
        input[bufferlength] = '\0';

        pid = fork();

        printf("buffer length before: %d\n", bufferlength);
        printf("previous: %d\n", previous);

        if (pid == 0) {
            // Child process
            execl(programPath, programPath, input, NULL);
            // If execl fails, print an error message
            perror("execl");
            exit(EXIT_FAILURE);
        } else if (pid < 0) {
            // Fork failed
            perror("fork");
            exit(EXIT_FAILURE);
        } else {
            // Parent process
            wpid = waitpid(pid, &status, 0);

            if (WIFEXITED(status)) {
                printf("Child process %d exited with status %d\n", wpid, WEXITSTATUS(status));
                printf("Child process %d terminated by signal %d\n", wpid, WTERMSIG(status));
                //bufferlength = bufferlength + dif;
                if (previous == 0) {
                    dif *= 2;
                } else {
                    dif /= 2;
                }
                previous = 0;
            } else if (WIFSIGNALED(status)) {
                printf("Child process %d terminated by signal %d\n", wpid, WTERMSIG(status));
                //bufferlength = bufferlength - dif;

                if (WTERMSIG(status) == 11) {
                    printf("Segmentation fault occurred.\n");
                    bufferlength -= dif;
                    if (previous == 11) {
                        dif /= 2;
                    } else {
                        dif *= 2;
                    }
                    previous = 11;
                }
                    
            }
        }

        printf("buffer length after: %d\n", bufferlength);
        printf("difference: %d\n", dif);

        // fclose(fp); 
        free(input);

        runs += 1; 
        //if (WTERMSIG(status) == 11) loop = 0;
        if (runs == 11) loop = 0;

    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <program_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *programPath = argv[1];
    runProgram(programPath);

    return 0;
}
