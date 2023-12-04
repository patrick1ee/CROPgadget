from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def disassemble_shellcode(shellcode):
    # Create a disassembler object
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    # Disassemble the shellcode
    for instruction in md.disasm(shellcode, 0x1000):
        print("0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# Disassemble the shellcode
disassemble_shellcode(shellcode)