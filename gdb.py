from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import subprocess
import signal
import sys
import re
from ctypes import *

#stack smash the stack smashing detector, infinite regression

#use a stack canary, binary search until 1 under when stack canary stops you then go one up

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
                if i == num - 1:
                    address = '0' + line[1:8]
                    addresses.append(address)
    return addresses

def get_target():
    gdbmi = GdbController()
    gdbmi.write("-file-exec-and-symbols vuln3-32")
    for i in range (len(addresses)):
        gdbmi.write('b *0x' + addresses[i])
    gdbmi.write('r input')
    response = gdbmi.write('x/4wx $ebp')
    target = response[1]['payload'][14:22]
    overflows = response[1]['payload'][25:32] + response[1]['payload'][36:44] + response[1]['payload'][47:55]
    return target, overflows

def too_high(overflows):
    pattern = re.compile(r'41.*41')
    return bool(pattern.search(overflows))

def too_low(target):
    if (target == '41414141'): return False
    return True

if __name__ == '__main__':
    addresses = get_function_addresses()

    found_overflow = False
    buffer_length = 512
    min = 1
    max = 1024

    while found_overflow == False:
        buffer_length = (min + max)//2

        f = open('input', "w")
        string = "A" * int(buffer_length)
        f.write(string)
        f.close()

        target, overflows = get_target()
        high = too_high(overflows)
        low = too_low(target)

        if not high and not low: found_overflow = True
        elif high: 
            max = buffer_length - 1
        else: 
            min = buffer_length + 1

        
    print(buffer_length)

    # shared_file = "/vagrant/monitor.so"
    # c_funcs = CDLL(shared_file)

    # c_funcs.monitor(int(addresses[0],16))
    #c_funcs.monitor(int(addresses[1],16))


    # #this could be a potential way but reading proc/$pid/mem is denied
    # process = subprocess.Popen(['/vagrant/vuln3-32', 'input'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # pid = process.pid
    # print('pid:', pid)
    # process.send_signal(signal.SIGSTOP)


    # # command = str('sudo cat /proc/' + str(pid) + '/maps')
    # # map = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # # exit_code = map.wait()
    # # output, error = process.communicate()
    # # print(output, error, exit_code)

    
    # with open('/proc/1204/maps', 'r') as fp:
    #     for i, line in enumerate(fp):
    #         print(line)

    # for i in range (len(addresses)):
    #     #reads location from pid
    #     command = str('sudo dd bs=1 skip="$((0x' + addresses[i] + '))" count=4 if="/proc/' + str(pid) + '/mem" | od -An -vtu4')
    #     data = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #     data.wait()
    #     output = (data.stdout.read(), data.stderr.read())
    #     pprint(output[0].hex())

    # process.send_signal(signal.SIGCONT)
    # exit_code = process.wait()
    # output, error = process.communicate()
    # print(output, error, exit_code)


    #another way could be using ptrace
        #would need to find a way to pipe addresses here into c though



#objdump -d your-program