from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from ExecveBuilder import *
from GadgetFinder import *

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
        if self.req_int:
            self.instructions.append(Instruction('pop ' + self.SRC, ['esp'], ['esp', self.SRC]))
            for reg in list(filter(lambda x: x != self.SRC, ['eax', 'ebx', 'ecx', 'edx'])):
                self.instructions.append(Instruction('pop ' + reg, ['esp'], ['esp', reg]))

            if self.SRC != 'eax': self.instructions.append(Instruction('xor eax, eax', ['esp'], ['esp']))
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
            if instruction.mnemonic == 'push': continue
            if instruction.mnemonic == 'mov':
                if instruction.op_str.split(',')[1].strip() == 'esp': continue
                if instruction.op_str.split(',')[1].strip()[0:2] == '0x':
                    if instruction.op_str.split(',')[0] == 'al': new_instruction = 'inc eax'
            if instruction.mnemonic == 'pop': pass

            # Reserve esp unconditionally
            if 'esp' not in pre_reserve_snapshots[idx]: pre_reserve_snapshots[idx].append('esp')
            if 'esp' not in post_reserve_snapshots[idx]: post_reserve_snapshots[idx].append('esp')

            print("0x%x:\t%s\t%s\t%s\t\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str, str(pre_reserve_snapshots[idx]), str(post_reserve_snapshots[idx])))

            if new_instruction not in list(map(lambda x: x.value, self.instructions)):
                self.instructions.append(Instruction(new_instruction, pre_reserve_snapshots[idx], post_reserve_snapshots[idx]))

        

    def setup(self):
        self.disassemble_shellcode()
        self.analyse_disassembly()

    def start(self, stdout):
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
        

