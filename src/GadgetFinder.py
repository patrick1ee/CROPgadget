import math
import re
from struct import pack

class Instruction():
    def __init__(self, value, pre_reserved = [], post_reserved = []) -> None:
        self.value = value
        self.pre_reserved = pre_reserved
        self.post_reserved = post_reserved

class Gadget():
    def __init__(self, addr, complexity) -> None:
        self.address = addr
        self.complexity = complexity
        self.side_pops = []

    def compile(self):
        return pack('<I', self.address)

class GadgetFinder():
    def __init__(self, gadgets={}) -> None:
        self.gadgets = gadgets
        self.data = 0x0
        self.wwarnlist = ['dword']
        self.jmpregs = ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esi', 'edi', 'ebp']

    def find_lowest_complexity(self):
        ins = list(self.gadgets.keys())[0]
        gad = self.gadgets[ins]
        for k, v in self.gadgets.items():
            if v.complexity < gad.complexity: 
                ins = k
                gad = v

        return ins, gad

    def parse_gadget(self, addr, parts, instruction):
        # TODO jmp case
        if parts[len(parts) - 1].strip() != 'ret':
            if instruction != 'int 0x80': return

        gadget = Gadget(addr, 0)
        reserved = instruction.pre_reserved.copy()

        for p in parts:
            words = list(filter(lambda x: len(x) > 0, p.split(' ')))
            ins = words[0]
            waddr = ''
            at_waddr = True

            for i in range(1, len(words)):
                if p.strip() != instruction.value and words[i] in self.wwarnlist and at_waddr: 
                    return
                if words[i][-1] == ',' :
                    waddr = words[i][:-1] 
                    at_waddr = False
                else: waddr = ''
                if waddr in reserved: return
                if p.strip() == instruction.value:
                    reserved = instruction.post_reserved.copy()
                    if len(waddr) > 0: reserved.append(waddr)

            if ins == 'pop': gadget.side_pops.append(words[1])
            gadget.complexity += 1

        if self.gadgets[instruction.value].complexity > gadget.complexity:
            self.gadgets[instruction.value] = gadget
        



    def search_gadgets(self, line, instructions):
        for instruction in instructions:
            regex = re.search(instruction.value.replace('[', '\[').replace(']', '\]'), line)
            if regex:
                addr = int(line[0:10], 16)
                seq = line[13:-1]
                if seq == 'int 0x80': self.gadgets['int 0x80'] = Gadget(addr, 1)
                parts = seq.split(';')
                self.parse_gadget(addr, parts, instruction)

    def search_data(self, line):
        regex = re.search('.data', line)
        if regex:
            parts = line.split(' ')
            if parts[-1] == '.data': self.data = int(parts[3][:-1], 16)


    def start(self, stdout, instructions, s=0, t=0):
        print('\nGathering gadget sets ' + str(s) + '/' + str(t) + '...\n')
        for ins in instructions:
            self.gadgets[ins.value] = Gadget(0x0, math.inf)

        pattern = re.compile(r'^[0-9a-fA-F]+')
        for line in stdout:
            if pattern.match(line): self.search_gadgets(line, instructions)
            elif re.search('.data', line):
                parts = line.split(' ')
                if parts[-1].strip() == '.data': self.data = int(parts[3][:-1], 16)
