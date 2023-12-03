import re

class GadgetFinder():
    def __init__(self) -> None:
        self.gadgets = {}
        self.DST_REG = 'edx'
        self.SRC_REG = 'ecx'

    def parse_gadget(addr, parts, instruction, reserved):
        # TODO jmp case
        if parts[len(parts) - 1].strip() != 'ret': return
        for p in parts:
            words = p.split(' ')
            ins = words[0]
            waddr = None
            for i in range(1, len(words)):
                if words[i][-1] == ',': waddr = words[i][:-1]

            if waddr in reserved: return
            
            if p.strip() == instruction.value: reserved.append(waddr)


    def search_gadgets(line, instructions):
        for instruction in instructions:
            regex = re.search(instruction.value, line)
            if regex:
                parts = line.split(':')
                addr = parts[0].strip()
                parts = parts[1].split(';')