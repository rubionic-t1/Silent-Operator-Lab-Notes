
# Quick HTTP Recon

Fast, practical checks to map any web surface before exploitation.

---

## Basic Fingerprinting
```bash
whatweb http://<IP>
curl -I http://<IP>
````

Look for:

* Frameworks (PHP, ASPX, Node, Java)
* Redirect chains
* Server headers
* CDN / WAF presence
* Tech leaks (Apache, nginx, IIS)

---

## Directory & File Discovery

```bash
gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt
```

Faster alternative:

```bash
ffuf -u http://<IP>/FUZZ -w wordlist.txt
```

Targets:

* /admin
* /backup / .zip / .bak
* /uploads
* /api
* /config

---

## Virtual Host (VHost) Discovery

```bash
ffuf -u http://<IP> -H "Host: FUZZ.example.com" -w subdomains.txt
```

Useful for:

* dev / test / staging subdomains
* forgotten admin portals
* internal-only dashboards

---

## Page Source & Comments

Inspect:

* HTML comments
* JS files
* Hidden fields
* Disabled buttons

Look for:

* API endpoints
* Tokens
* Feature flags
* Internal paths

---

## Parameter Discovery

```bash
ffuf -u "http://<IP>/page.php?FUZZ=1" -w SecLists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

Helps identify:

* IDOR parameters
* LFI candidates
* Debug params
* Auth bypass vectors

---

## Tech-Specific Quick Checks

### PHP Targets

Common LFI parameters:

```
?file=
?path=
?page=
?view=
```

### Node / Express

* Try SSTI payloads: `{{7*7}}`, `${7*7}`
* Check /api/ endpoints

### Java / JSP

* Look for `/jmx-console`, `/manager/html`
* Deserialization vectors

### WordPress

```bash
wpscan --url http://<IP>
```

---

## HTTPS Enumeration

```bash
sslscan <IP>
```

Check for:

* Weak ciphers
* Internal domain names in SAN
* Expired / misconfigured certs

---

## Screenshot Everything

```bash
eyewitness --web --single <IP>
```

Useful for:

* Mapping all UI surfaces
* Identifying login pages
* Quickly spotting admin portals

---

## Notes

* Always hit [http://IP:PORT](http://IP:PORT) and [https://IP:PORT](https://IP:PORT)
* High ports often hide dev/staging apps
* Combine: dirs + params + vhosts for maximum surface
* Save curl outputs + screenshots for evidence

---

