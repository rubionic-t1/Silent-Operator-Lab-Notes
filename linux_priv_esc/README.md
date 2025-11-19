# Linux Privilege Escalation — Silent Operator Notes

Complete Linux PrivEsc workflow built from lab exercises, real-world checks, and exploit patterns.

Use this folder to identify:
- escalation class
- required evidence
- exploitation path
- validation method
- fix recommendation

Everything is structured to be re-usable in labs, VMs, and internal assessments.

---

## PrivEsc Classes (What You Should Always Check)
1. Processes & running services  
2. Cron jobs (timed tasks)  
3. Writable files / misconfigured permissions  
4. /etc/passwd & authentication abuse  
5. SUID binaries  
6. Capabilities  
7. Sudo rights  
8. Kernel & version exploits  
9. Custom binaries / scripts  
10. PATH hijacking (if allowed)

Each class has a dedicated `.md` file below.

---

## Files in This Folder
- **[basic-enum.md](basic-enum.md)**  
- **[cron-abuse.md](cron-abuse.md)**  
- **[writable-files.md](writable-files.md)**  
- **[passwd-shadow-abuse.md](passwd-shadow-abuse.md)**  
- **[suid-binaries.md](suid-binaries.md)**  
- **[capabilities.md](capabilities.md)**  
- **[sudo-abuse.md](sudo-abuse.md)**  
- **[kernel-exploits.md](kernel-exploits.md)**  
- **[custom-binaries.md](custom-binaries.md)**
- **[path-hijacking.md](path-hijacking.md)**

More notes will be added as I refine and expand my PrivEsc workflow.

---
