import argparse
import subprocess
from io import StringIO
from ParseChain import *


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('binary', metavar='B', type=str, nargs='+',
                    help='binary')
    parser.add_argument('-c', help='sum the integers (default: find the max)')

    args = parser.parse_args()
    print(args.binary)
    print(args.c)

    command_rg = ["python3", "./ROPgadget/ROPgadget.py", "--binary", args.binary[0], "--ropchain"]
    with subprocess.Popen(command_rg, stdout=subprocess.PIPE) as process:
        output_stream = io.TextIOWrapper(process.stdout, newline='\n', encoding='utf-8')
        
        pc = ParseChain()
        pc.start(output_stream, args.c.split(' ')[0], args.c.split(' ')[1:])

main()