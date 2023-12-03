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

            # Check for blacklisted instructions/keywords
            for wlw in self.warnlist:
                if wlw in words and p.strip() != instruction.value: return

            ins = words[0]
            waddr = None
            for i in range(1, len(words)):
                if words[i][-1] == ',': waddr = words[i][:-1]
                if waddr in reserved: return
                if p == instruction.value: reserved.append(waddr)

            if ins == 'pop': gadget.side_pops.append(words[1])
            gadget.complexity += 1

        if self.gadgets[instruction.value].complexity > gadget.complexity:
            self.gadgets[instruction.value] = gadget
        



    def search_gadgets(self, line, instructions):
        for instruction in instructions:
            regex = re.search(instruction.value, line)
            if regex:
                parts = line.split(':')
                addr = parts[0].strip()
                parts = parts[1].split(';')
                self.parse_gadget(addr, parts, instruction)


    def start(self):
        file1 = open('out-rop-ret2.txt', 'r')
        Lines = file1.readlines()

        instructions = [
            Instruction('pop eax', ['esp']),
            Instruction('xor eax, eax', ['esp']),
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
