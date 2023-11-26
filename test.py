import re


pattern = re.compile(f'.*{re.escape("ret")}$')
file = open('out-rop.txt')
out_file = open('out-rop-ret.txt', 'w')
for line in file:
    if re.match(pattern, line): out_file.write(line)

file.close()
out_file.close()