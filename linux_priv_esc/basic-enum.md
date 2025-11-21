
# Basic Enumeration  

Always begin with full basic enumeration.  
Every privilege escalation chain starts here.

---

## 1. System Information

```bash
hostname
id
whoami
uname -a
cat /etc/issue
cat /proc/version
arch
````

---

## 2. Users & Login Activity

```bash
cat /etc/passwd
cat /etc/group

last
who
w
```

Produces:

* active sessions
* login history
* system users
* privilege groups

---

## 3. Processes & Services

```bash
ps aux
ps -ef
top
```

Look for:

* credentials in command-line arguments
* backup scripts
* dev/test scripts
* monitoring tools
* sshpass usage

---

## 4. Network

```bash
ip a
ifconfig 2>/dev/null
netstat -tunlp 2>/dev/null
ss -tulnp
```

Identify:

* listening ports
* local services
* internal footholds
* forwarded ports

---

## 5. Interesting Files & Secrets

```bash
find / -type f -name "*config*" 2>/dev/null
find / -type f -name "*pass*" 2>/dev/null
find / -type f -name "*credentials*" 2>/dev/null
find / -type f -name "*shadow*" 2>/dev/null
```

---

## 6. Writable Files & Directories

```bash
find / -writable -type f 2>/dev/null
find / -perm -2 -type f 2>/dev/null
find / -perm -2 -type d 2>/dev/null
```

These lead to:

* PATH hijacking
* cron/script modification
* custom binary replacement

(See [writable-files.md](linux_priv_esc/writable-files.md).)

---

## 7. SUID & Capabilities

```bash
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
```

These lead to:

* direct root via GTFOBins
* custom SUID exploits
* capability abuse

(See [suid-binaries.md](linux_priv_esc/suid-binaries.md) and [capabilities.md](linux_priv_esc/capabilities.md).)

---

## 8. Cron & Timed Tasks

```bash
ls -lah /etc/cron*
grep CRON /var/log/syslog
crontab -l 2>/dev/null
```

Writable cron scripts → root escalation.
(See [cron-abuse.md](linux_priv_esc/cron-abuse.md).)

---

## 9. Kernel & Version

```bash
uname -r
cat /proc/version
```

Check for vulnerable kernel versions.
(See [kernel-exploits.md](linux_priv_esc/kernel-exploits.md).)

---

## Operator Checklist

* [ ] Identify system/distro
* [ ] Check active users & logins
* [ ] Enumerate processes & services
* [ ] Enumerate network exposure
* [ ] Identify writable files
* [ ] Identify SUID & capabilities
* [ ] Identify cron tasks
* [ ] Get kernel version & search for CVEs

---

**Enumeration is 80% of PrivEsc. The exploit is just the last step.**
