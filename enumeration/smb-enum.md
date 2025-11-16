# SMB Enumeration
Quick commands for identifying shares, users, permissions & attack paths.

---

## 1. Basic SMB Probe
```bash
smbclient -L //<IP> -N
````

* Checks anonymous access
* Lists available shares
* First indicator of misconfigs

---

## 2. Enum4linux-NG (Modern)

```bash
enum4linux-ng -A <IP>
```

Checks:

* Users
* Groups
* Shares
* Policies
* Password hints
* Null session viability

---

## 3. Classic Enum4linux

```bash
enum4linux -a <IP>
```

Use when:

* Old Windows domains
* Samba hosts
* Legacy boxes

---

## 4. Test Null Session (No Password)

```bash
smbclient //<IP>/share -N
```

If it works → **immediate misconfig → data theft or privesc path.**

---

## 5. Manual Share Browsing

```bash
smbclient //<IP>/<SHARE> -U "" -N
```

Useful to test:

* Read/Write perms
* Anonymous upload
* Hidden backup files

---

## 6. Get OS + Domain Info

```bash
smbclient -L //<IP> -N --option='client min protocol=NT1'
```

Sometimes newer clients fail until downgraded.

---

## 7. RPC Users Enumeration

```bash
rpcclient -U "" -N <IP>
```

Then run:

```
enumdomusers
queryuser <RID>
enumalsgroups domain
```

Great for:

* Username discovery
* Mapping domain structure

---

## 8. SMB Version / Encryption Check

```bash
nmap --script smb-protocols -p445 <IP>
```

Finds:

* SMBv1 enabled → **MS17-010**
* Weak signing
* Downgrade attacks possible

---

## 9. Vulnerability Scripts (Safe)

```bash
nmap -p445 --script smb-enum* <IP>
```

---

## 10. Bruteforce (If Allowed)

```bash
hydra -L users.txt -P passwords.txt smb://<IP>
```

Use ONLY when permitted.

---

## 11. Check SMB Signing (Relay Attack Path)

```bash
nmap --script smb2-security-mode -p445 <IP>
```

* Signing disabled → **relay attacks possible**

---

## 12. List Share Permissions

```bash
smbmap -H <IP>
```

### With creds:

```bash
smbmap -H <IP> -u <USER> -p <PASS>
```

---

## 13. Download All Files From a Share

```bash
smbclient //<IP>/<SHARE> -N -c "prompt off; recurse on; mget *"
```

Often reveals:

* passwords.txt
* unattended.xml
* scripts with creds
* config backups

---

## 14. Write Test (Privilege Escalation Clue)

```bash
smbclient //<IP>/<SHARE> -N -c "put test.txt"
```

If upload succeeds →
**you can plant revshells, cron files, or tamper with scripts.**

---

# Attack Pivots (Notes)

* **SMBv1 ON → EternalBlue (MS17-010)**
* **Null session ON → Huge data exposure**
* **No signing → NTLM Relay → takeover**
* **Write access → drop shells or modify scripts**
* **Leaked usernames → spray across SSH/RDP/WinRM**
* **Share browsing → passwords, scripts, backups**

---

# Minimal Flow (Use This Every Time)

1. `smbclient -L //<IP> -N`
2. `smbmap -H <IP>`
3. `enum4linux-ng -A <IP>`
4. Check for signing → `--script smb2-security-mode`
5. Check for SMBv1 → `--script smb-protocols`
6. Try null sessions → `smbclient //<IP>/share -N`
7. Explore shares
8. Pull files
9. Identify credentials → pivot to WinRM/RDP

---



