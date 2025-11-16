# DirBuster • Dirsearch • FFUF — Quick Recon Notes

Real commands used in pentests/VDPs.  
Clean • Fast • Practical.

---

# 🗂 Recommended Wordlists (Kali SecLists Paths)

```bash
/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt
/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt
````

---

# DIRBUSTER (GUI)

Good for: visual recursion + multi-extension brute force on internal targets.

### Launch

```bash
dirbuster
```

Use when:

* you want visual mapping
* deep recursive trees
* slow/weak internal machines

### Recommended wordlists
```
 /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
 /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 /usr/share/dirbuster/wordlists/common.txt
```
### Quick tips

* Add extensions: `.php,.txt,.bak,.zip`
* Threads: 20–50
* Export results → compare size
---

# DIRSEARCH (FAST CLI)

Quick directory brute force.

### Basic

```bash
dirsearch -u <TARGET_URL>
```

### With wordlist

```bash
dirsearch -u <TARGET_URL> \
-w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
```

### With extensions

```bash
dirsearch -u <TARGET_URL> \
-w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt \
-e php,asp,aspx,jsp,py,txt,conf,bak,old,db,sql
```

### POST mode

```bash
dirsearch -u <TARGET_URL> -m POST
```

---

# FFUF (PRECISION FUZZING)

For directories, parameters, vhosts, SSRF, values.

---

## Directory Fuzzing

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u <TARGET_URL>/FUZZ -c
```

## Recursive Scan

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u <TARGET_URL>/FUZZ \
-recursion -recursion-depth 1 -e .php -v
```

## Extension Fuzz

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ \
-u <TARGET_URL>/indexFUZZ
```

---

## Subdomain Fuzzing

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u https://FUZZ.<DOMAIN>/
```

## VHost Fuzzing

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u <TARGET_URL>/ \
-H "Host: FUZZ.<DOMAIN>" -fs <SIZE>
```

---

## GET Parameter Fuzzing

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u <TARGET_URL>/page.php?FUZZ=value \
-fs <SIZE>
```

## POST Parameter Fuzzing

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u <TARGET_URL>/api \
-X POST -d "FUZZ=value" \
-H "Content-Type: application/x-www-form-urlencoded" \
-fs <SIZE>
```

---

## Value Fuzzing (Usernames / Tokens)

```bash
ffuf -w /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt:FUZZ \
-u <TARGET_URL>/login \
-X POST -d "username=FUZZ" \
-H "Content-Type: application/x-www-form-urlencoded" \
-fs <SIZE>
```

---

## SSRF Port Fuzzing

```bash
ffuf -w ports.txt \
-u <TARGET_URL> \
-X POST \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "url=http://127.0.0.1:FUZZ" \
-fr "Failed to connect"
```

Generate ports:

```bash
seq 1 10000 > ports.txt
```

---

## WSDL / API Discovery

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
-u "<TARGET_URL>/wsdl?FUZZ" -fs 0 -mc 200
```

---

# Helper Commands

### Add DNS Entry

```bash
echo "<IP> <DOMAIN>" | sudo tee -a /etc/hosts
```

### Create numeric wordlist

```bash
seq 1 1000 > ids.txt
```

### Quick curl POST

```bash
curl <TARGET_URL> -X POST -d "key=value" \
-H "Content-Type: application/x-www-form-urlencoded"
```

---


