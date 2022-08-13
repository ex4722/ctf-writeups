from pwn import *
from itertools import permutations

perm = []

# 0x30 - 0x39 + 0x41 + 0x46
for i in range(5):
    perm.append(list(permutations(list("0123456789ABCDEF"),i)))


optcodes = b""


for l in perm:
    for i in l:
        optcodes += "".join(i).encode('latin') + b'\x90'*10
        try:
            context.arch = 'amd64'
            # print(disasm("".join(i).encode('latin')))
        except:
            pass

context.arch = 'amd64'
print(disasm(optcodes))
