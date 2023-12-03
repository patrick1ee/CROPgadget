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
    def __init__(self) -> None:
        self.gadgets = {}
        self.DST_REG = 'edx'
        self.SRC_REG = 'ecx'
        self.warnlist = ['ptr']

    def parse_gadget(self, addr, parts, instruction):
        # TODO jmp case
        if parts[len(parts) - 1].strip() != 'ret': return

        gadget = Gadget(addr, 0)
        reserved = instruction.reserved.copy()

        for p in parts:
            words = list(filter(lambda x: len(x) > 0, p.split(' ')))

            ins = words[0]
            waddr = ''

            for i in range(1, len(words)):
                waddr = words[i][:-1] if words[i][-1] == ',' else ''
                if waddr in reserved: return
                if p.strip() == instruction.value and len(waddr) > 0: reserved.append(waddr)  
                if p.strip() != instruction.value and words[i] in self.warnlist: return

            if ins == 'pop': gadget.side_pops.append(words[1])
            gadget.complexity += 1

        if self.gadgets[instruction.value].complexity > gadget.complexity:
            self.gadgets[instruction.value] = gadget
        



    def search_gadgets(self, line, instructions):
        for instruction in instructions:
            regex = re.search(instruction.value.replace('[', '\[').replace(']', '\]'), line)
            if regex:
                parts = line.split(':')
                addr = parts[0].strip()
                parts = parts[1].split(';')
                self.parse_gadget(addr, parts, instruction)

    def start(self):
        file1 = open('out-rop-ret.txt', 'r')
        Lines = file1.readlines()

        instructions = [
            Instruction('mov dword ptr [edx], eax', ['esp']),
            Instruction('pop edx', ['esp']),
            Instruction('pop eax', ['esp']),
            Instruction('xor eax, eax', ['esp']),
            Instruction('inc eax', ['esp']),
            Instruction('pop ebx', ['eax', 'esp']),
            Instruction('pop ecx', ['ebx', 'eax', 'esp'])
        ]

        for ins in instructions:
            self.gadgets[ins.value] = Gadget(0x0, math.inf)

        pattern = re.compile(r'^[0-9a-fA-F]+')
        for line in Lines:
            if pattern.match(line): self.search_gadgets(line, instructions)
        
        for k, v in self.gadgets.items():
            print(k + ": " + str(v.address) + ', ' + str(v.side_pops) + ', ' + str(v.complexity))

gf = GadgetFinder()
gf.start()
