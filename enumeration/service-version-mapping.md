# Service → Version Mapping (Attack Pivot Map)
Quick pivots from recon to exploitation.

---

## 1. SSH (22)

### What version reveals
- OpenSSH < 7.7 → user enumeration
- OpenSSH < 7.2 → `UsePrivilegeSeparation` bypass vectors
- Dropbear SSH → IoT / embedded (weak creds common)

### Pivot
- Default creds (internal/IoT)
- Authorized_keys misconfigs
- Reuse creds across services
- Weak key permissions (Linux privesc link)

---

## 2. HTTP / HTTPS (80/443)

### What version reveals
- Apache 2.2 / 2.4 → path traversal, outdated modules
- nginx → misconfigs, proxy leaks
- IIS 7/8/10 → WebDAV, RCE patterns

### Pivot
- Directory brute-force → attack surface
- Tech-specific attacks (PHP, ASP.NET)
- VHosts, subdomains, hidden admin panels

---

## 3. SMB (139/445)

### What version reveals
- SMBv1 enabled → EternalBlue (MS17-010)
- Windows 2008/2012 → Null sessions sometimes work
- Samba < 4.7 → `is_known_pipename` RCE (metasploit)

### Pivot
- SMB enum → shares → creds → privesc
- Bruteforce SMB login
- Pass-the-hash possibility

---

## 4. RDP (3389)

### What version reveals
- Older SSL/TLS → weak cyphers
- Cred stuffing risk

### Pivot
- `xfreerdp` brute testing
- Check for NLA disable → easy creds reuse
- Check for `rdpclip` copy/paste leakage (internal)

---

## 5. FTP (21)

### What version reveals
- vsftpd 2.3.4 → backdoor RCE
- ProFTPD → mod_copy abuse
- FileZilla → anonymous uploads

### Pivot
- Anonymous login?
- Write permissions?
- Upload → webshell (if web root)

---

## 6. MySQL (3306)

### What version reveals
- MySQL 5.x → weak auth plugins
- MariaDB → default creds in some appliances

### Pivot
- Test local connections via tunnel
- `--password=""` behavior trick
- File read via `LOAD DATA INFILE`

---

## 7. MSSQL (1433)

### What version reveals
- SQL Server 2008/2012 → Ole Automation RCE
- Mixed mode auth → brute usernames

### Pivot
- xp_cmdshell
- Impersonate login
- Linked servers → lateral movement

---

## 8. PostgreSQL (5432)

### What version reveals
- `COPY TO PROGRAM` → RCE on older versions
- Weak local trust configs

### Pivot
- RCE via `COPY`
- Read/write files
- Postgres → root via cron/outfile

---

## 9. Redis (6379)

### What version reveals
- No auth enabled (common)
- Backup file planting → SSH key drop

### Pivot
- Write SSH key → remote shell
- Write cron → reverse shell
- Dump memory → credentials

---

## 10. Memcached (11211)

### What version reveals
- No auth (default)
- Exposed cache entries

### Pivot
- Dump cached usernames/passwords
- Abuse keys for session hijack

---

## 11. LDAP (389 / 636)

### What version reveals
- LDAP anonymous bind possible
- Active Directory path building

### Pivot
- User enumeration
- Group membership mapping
- Spray passwords

---

## 12. SMTP (25, 587)

### What version reveals
- Open relay?
- VRFY/EXPN enabled?
- Mail server leaks usernames

### Pivot
- User enumeration
- Password spray
- Use SMTP creds elsewhere

---

## 13. POP3 / IMAP (110, 143, 993)

### What version reveals
- Cleartext POP3/IMAP → sniffable creds (internal)
- Supports weak auth mechanisms

### Pivot
- Mailbox takeover
- Reset links from inbox
- Lateral movement via email

---

## 14. WinRM (5985/5986)

### What version reveals
- WinRM = password reuse jackpot
- Creds from SMB/RDP often work here

### Pivot
- `evil-winrm`
- Lateral movement
- Full interactive shell

---

## 15. Elasticsearch (9200)

### What version reveals
- No auth in older versions
- Exposed indices

### Pivot
- Dump data
- RCE via misconfigs (rare)
- LFI via snapshot paths

---

## 16. MongoDB (27017)

### What version reveals
- No authentication (classic vuln)
- Arbitrary DB manipulation

### Pivot
- Dump DB
- Create user with root role
- Pivot to backend services

---

## 17. Jenkins (8080)

### What version reveals
- Script Console → RCE (if logged in)
- Anonymous read mode (often ON)

### Pivot
- Enumerate jobs → credentials
- RCE via Groovy console

---

## 18. Tomcat (8080)

### What version reveals
- Manager panel often default creds

### Pivot
- WAR upload → shell
- Bruteforce manager creds

---

## 19. Webmin (10000)

### What version reveals
- Old versions → RCE via auth bypass
- SSL misconfigs

### Pivot
- Shell via commands
- Privilege escalation likely

---

## 20. RabbitMQ (5672 / 15672)

### What version reveals
- Default creds
- Management panel exposed

### Pivot
- Enumerate queues
- Credential leaks
- Internal host mapping

---

# Quick Notes

### Common vulnerable versions you should instantly recognize:
- **SMBv1 → MS17-010 (EternalBlue)**
- **vsftpd 2.3.4 → backdoor**
- **Apache Tomcat Manager → WAR upload**
- **ProFTPD mod_copy → file write**
- **Redis → SSH key write**
- **MSSQL → xp_cmdshell**

---
