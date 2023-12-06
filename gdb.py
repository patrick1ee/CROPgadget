from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import subprocess
import signal
import sys
import re
from ctypes import *

#stack smash the stack smashing detector, infinite regression

#use a stack canary, binary search until 1 under when stack canary stops you then go one up

def get_function_addresses(binary):
    command = 'objdump -d ', binary, ' > disassembly.asm'
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    
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
                    address = line[1:8]
                    addresses.append(address)
    return addresses

def get_target(binary, addresses):
    gdbmi = GdbController()
    gdbmi.write("-file-exec-and-symbols " + binary)
    for address in addresses:
        gdbmi.write('b *0x' + address)
    gdbmi.write('r input')
    response = gdbmi.write('x/4wx $ebp')
    target = response[1]['payload'][14:22]
    overflows = response[1]['payload'][25:32] + response[1]['payload'][36:44] + response[1]['payload'][47:55]
    print(target, overflows)
    return target, overflows

def too_high(overflows):
    pattern = re.compile(r'41.*41')
    return bool(pattern.search(overflows))

def too_low(target):
    if (target == '41414141'): return False
    return True

if __name__ == '__main__':
    binary = sys.argv[1]
    addresses = get_function_addresses(binary)

    found_overflow = False
    buffer_length = 512
    min = 1
    max = 1024

    while not found_overflow:
        print(buffer_length)
        buffer_length = (min + max)//2
        f = open('input', "w")
        string = "A" * int(buffer_length)
        f.write(string)
        f.close()

        target, overflows = get_target(binary, addresses)
        high = too_high(overflows)
        low = too_low(target)

        if not high and not low: found_overflow = True
        elif high: 
            max = buffer_length - 1
        else: 
            min = buffer_length + 1

        
    print("buffer length:", buffer_length)

    # shared_file = "/vagrant/monitor.so"
    # c_funcs = CDLL(shared_file)

    # c_funcs.monitor(int(addresses[0],16))
    #c_funcs.monitor(int(addresses[1],16))
