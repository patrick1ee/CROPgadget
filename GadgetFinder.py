import math
import re

class Instruction():
    def __init__(self, value, reserved) -> None:
        self.value = value
        self.reserved = reserved

class Gadget():
    def __init__(self, addr, complexity) -> None:
        self.address = addr
        self.complexity = complexity
        self.side_pops = []

class GadgetFinder():
    def __init__(self, gadgets={}) -> None:
        self.gadgets = gadgets
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
        if parts[len(parts) - 1].strip() != 'ret': return

        gadget = Gadget(addr, 0)
        reserved = instruction.reserved.copy()

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
                if p.strip() == instruction.value and len(waddr) > 0: reserved.append(waddr)  

            if ins == 'pop': gadget.side_pops.append(words[1])
            gadget.complexity += 1

        if self.gadgets[instruction.value].complexity > gadget.complexity:
            self.gadgets[instruction.value] = gadget
        



    def search_gadgets(self, line, instructions):
        for instruction in instructions:
            regex = re.search(instruction.value.replace('[', '\[').replace(']', '\]'), line)
            if regex:
                addr = line[0:10]
                parts = line[13:-1].split(';')
                self.parse_gadget(addr, parts, instruction)

    def start(self, stdout, instructions):
    
        for ins in instructions:
            self.gadgets[ins.value] = Gadget(0x0, math.inf)

        pattern = re.compile(r'^[0-9a-fA-F]+')
        for line in stdout:
            if pattern.match(line): self.search_gadgets(line, instructions)
