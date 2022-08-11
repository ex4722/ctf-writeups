from pwn import *
from itertools import permutations

perm = []

for i in range(5):
    perm.append(list(permutations(list("0123456789ABCDEF"),i)))


optcodes = b""


for l in perm:
    for i in l:
        optcodes += "".join(i).encode('latin') + b'\x90'*10

context.arch = 'amd64'
print(disasm(optcodes))
