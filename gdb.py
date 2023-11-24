from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import subprocess
import signal
import sys
import re

#stack smash the stack smashing detector, infinite regression

def get_function_addresses():
    command = 'objdump -d vuln3-32 > disassembly.asm'
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    output = (proc.stdout.read(), proc.stderr.read())
    
    lines = []
    functions = []
    block = False
    with open("disassembly.asm", 'r') as fp:
        for i, line in enumerate(fp):
            if '<main>' in line:
                block = True
            if block == True and line == '\n':
                block = False
            if '>:\n' in line:
                name = re.search('<(.*)>', line)
                functions.append((name.group(1), i))

    collection = []
    collect = False
    for i, function in enumerate(functions):
        if collect == True: collection.append(functions[i][1])

        if function[0] == 'main': 
            collection.append(functions[i+1][1])
            break
        
        if function[0] == 'frame_dummy':
            collect = True    

    lines = []
    for i in range(len(collection)-1):
        lines.append(collection[i+1]-2)

    addresses = []
    with open("disassembly.asm", 'r') as fp:
        for i, line in enumerate(fp):
            for num in lines:
                if i == num:
                    address = '0' + line[1:8]
                    print(address)
                    addresses.append(address)
    return addresses

if __name__ == '__main__':
    gdbmi = GdbController()
    # response = gdbmi.write("-file-exec-and-symbols vuln3-32")
    # response = gdbmi.write('r input')
    # response = gdbmi.write('define fn')
    # response = gdbmi.write('rbreak vuln3.c:.')
    # response = gdbmi.write('end')

    # func_response = gdbmi.write('fn')
    # #response = gdbmi.write('')
    # for i in range(len(func_response)):
    #     print(func_response[i]['payload'])

    # response = gdbmi.write('disas copyData')
    # for i in range(len(response)):
    #     pprint(response[i]['payload'])

    # response = gdbmi.write('x/10x $sp')
    # for i in range(len(response)):
    #     pprint(response[i]['payload'])

    addresses = get_function_addresses()


    #this could be a potential way but reading proc/$pid/mem is denied
    process = subprocess.Popen(['/vagrant/vuln3-32', 'input'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid = process.pid
    #reads location from pid
    command = str('sudo dd bs=1 skip="$((0x' + addresses[1] + '))" count=4 if="/proc/' + str(pid) + '/mem" | od -An -vtu4')
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.send_signal(signal.SIGSTOP)
    proc.wait()
    output = (proc.stdout.read(), proc.stderr.read())
    pprint(output[0])

    #another way could be using ptrace
        #would need to find a way to pipe addresses here into c though

    

#objdump -d your-program