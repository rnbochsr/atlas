# Atlas v1.4

## Enumeration

### NMAP Scan 

*Ports* 
* 3389 Windows RDP
* 8080 ThinVNC

## Exploits

### ThinVNC Exploit
> by Muirland Oracle

https://github.com/MuirlandOracle/CVE-2019-17662

[+] Credentials Found!
Username:       [REDACTED]
Password:       [REDACTED]

xfreerdp /v:IPaddr /u:USERNAME /p:PASSWORD /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp

### PrintNightmare
> by Caleb Stewart and John Hammond

https://github.com/calebstewart/CVE-2021-1675

### Mimikatz

Use this exploit to dump password hashes. Download mimikatz, copy mimkatz to the tmp directory, and unzip the archive.
```bash

```
