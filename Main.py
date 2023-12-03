import argparse
import subprocess
from io import StringIO
from ParseChain import *
from GadgetFinder import *
from ExecveBuilder import *


def main():
    parser = argparse.ArgumentParser(description='Pat & Gooseman exploit')
    parser.add_argument('binary', metavar='B', type=str, nargs='+',
                    help='binary')
    parser.add_argument('-c', help='command to execute')

    args = parser.parse_args()

    binary = args.binary[0]

    #buffer = gdb.get_padding_gdb(binary)
    #print("Found padding length of " + str(buffer))

    eb = ExecveBuilder(['eax', 'ebx', 'ecx', 'edx'])

    command_rg = ["python3", "./ROPgadget/ROPgadget.py", "--binary", args.binary[0], "--ropchain"]
    with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
        output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
        eb.find_xor_src(output_stream)

        #pc = ParseChain()
        #pc.start(output_stream, args.c.split(' ')[0], args.c.split(' ')[1:], buffer)

    with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
        output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
        eb.find_mov_dst(output_stream)

    with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
        output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
        eb.build_chain(output_stream)

    gadgets = eb.gadget_finder.gadgets
    for k, v in gadgets.items():
        print(k + " :: " + str(v.address) + ", " + str(v.complexity )+ ", " + str(v.side_pops))


main()