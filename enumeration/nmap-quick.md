## Quick nmap Recon

Fast, minimal, lab-friendly commands. No fluff.

---

## Simple Quick Scan
```bash
nmap <IP>
```

---

## Quick All-Ports Scan

```bash
nmap -p65535 <IP>
```

---

## Version + Default Checks (Full Port Sweep)

```bash
nmap -sV -sC -p- -oN output.txt <IP>
```

---

## UDP + SYN Mixed Scan

```bash
nmap -sU -T4 -sS -p- -v <IP>
```

---

## High-Speed Full Port Sweep

```bash
nmap -Pn -sS --stats-every 3m --max-retries 1 --max-scan 20 --defeat-rst-ratelimit \
-T4 -p1-65535 <IP> -vv
```

---

## Aggressive Recon

```bash
nmap -sV -p- -A <IP>
```

---

## If SYN Scan Is Blocked (fallback)

```bash
nmap -p- -sT -Pn <IP>
```

---

## NSE Script Scan (Quick Uses)

### Run a specific script

```bash
nmap --script=http-title -p80 <IP>
```

### Run a category of scripts

```bash
nmap --script=vuln -p80 <IP>
```

### Run multiple scripts

```bash
nmap --script="default,vuln" -p80 <IP>
```

### Run script with arguments

```bash
nmap --script=http-brute --script-args userdb=users.txt,passdb=pass.txt -p80 <IP>
```

### Update script database

```bash
nmap --script-updatedb
```

---

## Notes

* Start simple → escalate based on response
* Use `-sT` when SYN is filtered
* Use `-A` only when noise is acceptable
* Store outputs for chain building

----


