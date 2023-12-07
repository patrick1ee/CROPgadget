from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from struct import pack, unpack

from src.ExecveBuilder import *
from src.GadgetFinder import *

def s32(value):
    return -(value & 0x80000000) | (value & 0x7fffffff)

class DisassemblyInstruction():
    def __init__(self, address, mnemonic, op_str):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str

class ShellcodeCompiler():
    def __init__(self, shellcode) -> None:
        self.shellcode = shellcode
        self.req_stack = False
        self.req_int = False
        self.instructions = []
        self.SRC = 'eax'
        self.DST = 'edx'
        self.execve_builder = ExecveBuilder(['eax', 'ebx', 'ecx', 'edx'])
        self.gadget_finder = GadgetFinder()
        self.gadgets = {}
        self.stack_size = 0
        self.chain = b''
        pass

    def disassemble_shellcode(self):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.disassembly = []
        for instruction in md.disasm(self.shellcode, 0x1000):
            self.disassembly.append(DisassemblyInstruction(instruction.address, instruction.mnemonic, instruction.op_str))

    def analyse_disassembly(self):
        print('\n===============Shellcode===============')
        for instruction in self.disassembly:
            if instruction.mnemonic == 'push': self.req_stack = True
            if instruction.mnemonic == 'int': self.req_int = True
            print("0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))

    def add_instructions(self):
        if self.req_int or self.req_stack:
            self.instructions.append(Instruction('pop ' + self.SRC, ['esp'], ['esp', self.SRC]))
            for reg in list(filter(lambda x: x != self.SRC, ['eax', 'ebx', 'ecx', 'edx'])):
                self.instructions.append(Instruction('pop ' + reg, ['esp'], ['esp', reg]))

            if self.SRC != 'eax': 
                self.instructions.append(Instruction('inc ' + self.SRC, ['esp'], ['esp']))
                self.instructions.append(Instruction('xor eax, eax', ['esp'], ['esp']))
            self.instructions.append(Instruction('inc eax', ['esp', 'eax'], ['esp', 'eax']))
            self.instructions.append(Instruction('int 0x80', ['esp', 'eax', 'ebx', 'ecx', 'edx'], ['esp']))
        
        self.disassemble_shellcode()

        pre_reserve_snapshots = []
        post_reserve_snapshots = []
        reserved = []
        modified = []

        # Forward pass
        for idx, instruction in enumerate(self.disassembly):
            if instruction.mnemonic == 'cdq':
                if 'eax' in reserved: reserved.remove('eax')
                if 'edx' not in reserved: reserved.append('edx')
                if 'edx' not in modified: modified.append('edx')
            elif instruction.mnemonic == 'push': 
                if self.SRC in reserved: reserved.remove(self.SRC)
                if self.DST in reserved: reserved.remove(self.DST)
            elif ',' in instruction.op_str:
                dst = instruction.op_str.split(',')[0].replace('[', '').replace(']', '')
                src = instruction.op_str.split(',')[1].replace('[', '').replace(']', '').strip()
                if dst[0:2] != '0x' and dst not in reserved: reserved.append(dst)
                if dst[0:2] != '0x' and dst not in modified: modified.append(dst)
                if src in reserved: reserved.remove(src)
            elif instruction.mnemonic == "pop":
                if instruction.op_str not in reserved: reserved.append(instruction.op_str)
                if instruction.op_str not in modified: modified.append(instruction.op_str)
            elif instruction.op_str[0:2] != "0x" and len(instruction.op_str) > 0:
                if instruction.op_str not in reserved: reserved.append(instruction.op_str)
                if instruction.op_str not in modified: modified.append(instruction.op_str)
            
            post_reserve_snapshots.append(reserved.copy())

        # Backwards pass
        reserved = []
        for idx, instruction in enumerate(reversed(self.disassembly)):
            if instruction.mnemonic == 'cdq':
                if 'edx' in reserved: reserved.remove('edx')
                if 'eax' not in reserved: reserved.append('eax')
            if instruction.mnemonic == 'int':
                print(str(modified))
                for r in modified: 
                    if r not in reserved: reserved.append(r)
            elif instruction.mnemonic == 'push': 
                if instruction.op_str[0:2] != '0x' and instruction.op_str not in reserved: reserved.append(instruction.op_str)
            elif ',' in instruction.op_str:
                dst = instruction.op_str.split(',')[0].replace('[', '').replace(']', '')
                src = instruction.op_str.split(',')[1].replace('[', '').replace(']', '').strip()
                if src[0:2] != '0x' and src not in reserved: reserved.append(src)
                if dst in reserved: reserved.remove(dst)
            elif instruction.mnemonic == "pop":
                if instruction.op_str in reserved: reserved.remove(instruction.op_str)
            elif instruction.op_str[0:2] != "0x" and len(instruction.op_str) > 0:
                if instruction.op_str not in reserved: reserved.append(instruction.op_str)
            pre_reserve_snapshots.insert(0, reserved.copy())

        print('\n===============Shellcode Reservations===============')
        for idx, instruction in enumerate(self.disassembly):
            new_instruction = instruction.mnemonic + ' ' + instruction.op_str
            if instruction.mnemonic == 'push':
                if self.disassembly[idx + 1].mnemonic == 'pop':
                    pop_op = self.disassembly[idx + 1].op_str
                    ar_op = 0
                    try:
                        push_op = instruction.op_str
                        if push_op[0:2] == '0x' or push_op[0:2] == '-x': ar_op = s32(int(push_op, 16))
                        else: ar_op = s32(int(push_op, 10))
                        if ar_op > 0: new_instruction = 'inc ' + pop_op
                        else: new_instruction = 'dec ' + pop_op
                    except:
                        self.stack_size += 4
                else: continue
            elif instruction.mnemonic == 'mov':
                if instruction.op_str.split(',')[1].strip() == 'esp': continue
                if instruction.op_str.split(',')[1].strip()[0:2] == '0x':
                    if instruction.op_str.split(',')[0] == 'al': new_instruction = 'inc eax'
            elif instruction.mnemonic == 'pop':
                pass

            # Reserve esp unconditionally
            if 'esp' not in pre_reserve_snapshots[idx]: pre_reserve_snapshots[idx].append('esp')
            if 'esp' not in post_reserve_snapshots[idx]: post_reserve_snapshots[idx].append('esp')

            print("0x%x:\t%s\t%s\t%s\t\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str, str(pre_reserve_snapshots[idx]), str(post_reserve_snapshots[idx])))

            if new_instruction not in list(map(lambda x: x.value, self.instructions)):
                self.instructions.append(Instruction(new_instruction, pre_reserve_snapshots[idx], post_reserve_snapshots[idx]))

        

    def setup(self):
        self.disassemble_shellcode()
        self.analyse_disassembly()


    def pad_pop_reg(self, reg, data, used_regs = {}):
        gadget = self.gadgets['pop ' + reg]
        p = gadget.compile()
        print('pop ' + reg)
        affected_byte_regs = []
        for r in gadget.side_pops:
            if r == reg: 
                p += data
                s = str(hex(unpack('<I', data)[0]))
                print(s)
            else: 
                if r in used_regs.keys(): 
                    if used_regs[r] == 0:  
                        p += pack('<I', 0xffffffff)
                        print(str(hex(0xffffffff)))
                    elif used_regs[r] < 256:
                        p += pack('<I', 0xffffffff)
                        print(str(hex(0xffffffff)))
                        affected_byte_regs.append(r)
                    else: 
                        p += pack('<I', used_regs[r])
                        print( str(hex(used_regs[r])))
                else: 
                    p += pack('<I', 0x41414141)
                    print(hex(str(0x41414141)))
        for r in affected_byte_regs:
            value = used_regs[r]
            inc_ins = 'inc' if value >= 0 else 'dec'
            lbound = 1 if value < 0 else 0
            for _ in range(lbound, abs(value) + (1 - lbound)): 
                p += self.gadgets[inc_ins + ' ' + r].compile()
                print(inc_ins + ' ' + r)
        return p

    def start(self, stdout, padding):
        self.gadget_finder = GadgetFinder(self.execve_builder.init_gadgets)
        self.SRC = self.execve_builder.SRC
        self.DST = self.execve_builder.DST
        self.add_instructions()

        self.gadget_finder.start(stdout, self.instructions)
        self.gadgets = self.gadget_finder.gadgets
        self.DATA = self.gadget_finder.data
        
        print('\n===============Gadgets===============')
        for k, v in self.gadgets.items():
            print(k + " :: " + str(hex(v.address)) + ", " + str(v.complexity )+ ", " + str(v.side_pops))
        
        print("DATA " + str(hex(self.gadget_finder.data)) + "\n")

        skip = False
        p = b'A'*padding
        offset = self.stack_size

        regs = {'eax': 0, 'ebx': 0, 'ecx': 0, 'edx': 0}
        src_reg_reset = 0
        
        for idx, instruction in enumerate(self.disassembly):
            if skip: 
                skip = False
                continue
            print("\n\n0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))
            print(str(regs) + "\n")
            if instruction.mnemonic == 'push':
                oparts = instruction.op_str.split(' ')
                mode = None if len(oparts) != 2 else oparts[0]
                op_val = instruction.op_str if mode != 'byte' else oparts[1]
                if op_val[0:2] == '0x' or op_val[0] in [str(i) for i in range(1,10)] or op_val[1] in [str(i) for i in range(1,10)]:
                    value = s32(int(op_val, 16)) if op_val[0:2] == '0x' else s32(int(op_val, 10))
                    if self.disassembly[idx + 1].mnemonic == 'pop':
                        if len(op_val) <= 5:
                            pop_reg = self.disassembly[idx + 1].op_str
                            p += self.pad_pop_reg(pop_reg, pack('<I', 0xffffffff), regs)
                            inc_ins = 'inc' if value >= 0 else 'dec'
                            lbound = 1 if value < 0 else 0
                            for _ in range(lbound, abs(value) + 1): 
                                p += self.gadgets[inc_ins + ' ' + pop_reg].compile()
                                print(inc_ins + ' ' + pop_reg)
                            regs[pop_reg] = value
                        skip = True
                    elif len(op_val) == 4:
                        # Use increase method to set eax to target byte
                        p += self.pad_pop_reg(self.DST, pack('<I', self.DATA + offset), regs)

                        p += self.gadgets['xor ' + self.SRC + ", " + self.SRC].compile()
                        print('xor ' + self.SRC + ", " + self.SRC)
                        inc_ins = self.gadgets['inc eax'].compile() if value >= 0 else self.gadgets['dec eax'].compile()
                        for _ in range(0, abs(value)): 
                            p += inc_ins

                            if value >= 0: print('inc eax')
                            else: print('dec eax')

                        p += self.gadgets['mov dword ptr [' + self.DST + '], ' + self.SRC].compile()
                        print('mov dword ptr [' + self.DST + '], ' + self.SRC)

                        if src_reg_reset == 0: p += self.gadgets['xor ' + self.SRC + ", " + self.SRC].compile()
                        print('xor ' + self.SRC + ", " + self.SRC)
                        offset -= 4
                    else:
                        # Use pop,movstack method to put target word on stack
                        p += self.pad_pop_reg(self.DST, pack('<I', self.DATA + offset), regs)
                        p += self.pad_pop_reg(self.SRC, pack('<I', int(op_val, 16)), regs)
                        p += self.gadgets['mov dword ptr [' + self.DST + '], ' + self.SRC].compile()
                        print('mov dword ptr [' + self.DST + '], ' + self.SRC)

                        if src_reg_reset == 0: p += self.gadgets['xor ' + self.SRC + ", " + self.SRC].compile()
                        print('xor ' + self.SRC + ", " + self.SRC)
                        offset -= 4
                elif instruction.op_str in regs.keys():
                    p += self.pad_pop_reg(self.DST, pack('<I', self.DATA + offset), regs)
                    
                    if regs[instruction.op_str] > 0: p += self.pad_pop_reg(self.SRC, pack('<I', regs[instruction.op_str]), regs)
                    else: 
                        p += self.gadgets['xor ' + self.SRC + ", " + self.SRC].compile()
                        print('xor ' + self.SRC + ", " + self.SRC)
                    p += self.gadgets['mov dword ptr [' + self.DST + '], ' + self.SRC].compile()
                    print('mov dword ptr [' + self.DST + '], ' + self.SRC)

                    if src_reg_reset == 0: p += self.gadgets['xor ' + self.SRC + ", " + self.SRC].compile()
                    print('xor ' + self.SRC + ", " + self.SRC)
                    offset -= 4

            elif len(instruction.op_str.split(',')) == 2:
                dst = instruction.op_str.split(',')[0].replace('[', '').replace(']', '')
                src = instruction.op_str.split(',')[1].replace('[', '').replace(']', '').strip()
                if instruction.mnemonic == 'mov' and src == 'esp': 
                    p += self.pad_pop_reg(dst, pack('<I', self.DATA + offset + 4), regs)
                    regs[dst] = self.DATA + offset + 4
                elif instruction.mnemonic == 'mov' and src[0:2] == '0x':
                    if dst in ['al']: dst = 'eax'
                    for _ in range(0, int(src, 16)): 
                        p += self.gadgets['inc ' + dst].compile() 
                        print('inc ' + dst)
                else:
                    p += self.gadgets[instruction.mnemonic + " " + instruction.op_str].compile()
                    print(instruction.mnemonic + " " + instruction.op_str)

                    if instruction.mnemonic == 'xor' and src == dst: 
                        regs[dst] = 0
                        src_reg_reset = 0 
            else:
                p += self.gadgets[instruction.mnemonic + " " + instruction.op_str].compile()
                print(instruction.mnemonic + " " + instruction.op_str)
        self.chain = p

        print('\n')
        formatted_bytes = ' '.join([str(hex(int.from_bytes(self.chain[i:i+4], "little"))) for i in range(0, len(self.chain), 4)])
        print(formatted_bytes)

    def write_chain(self, file):
        out_file = open(file, 'wb')
        out_file.write(self.chain)