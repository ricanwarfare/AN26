---
tags: [redteam, enumeration, recon, network, guide, nmap]
created: 2026-04-29
updated: 2026-05-02
author: clawd
---

# Network Enumeration Guide

> **Red Team Perspective — From External Recon to Post-Foothold Deep Dives**

> [!info] Related Guides
> This guide is part of the **Cyber Exercise** vault. See also:
> - [[Red Team Engagement Guide]] — full engagement lifecycle and methodology
> - [[Metasploit 101]] — exploitation framework for initial access and post-exploitation
> - [[Sliver C2 - Red Team Operator Guide]] — advanced C2 infrastructure and implant management

---

---

## Table of Contents

- [[#Overview]]
- [[#External Enumeration (Pre-Foothold)]]
- [[#Internal Enumeration (Post-Foothold)]]
- [[#Protocol-Specific Deep Dives]]
- [[#Network Mapping & Topology Discovery]]
- [[#Automation — Bash One-Liners & Python Scripts]]
- [[#Tool Comparison Table]]
- [[#OPSEC — Stealth Scanning, Timing, IDS Evasion]]
- [[#Decision Framework — If You Find X, Try Y]]
- [[#Quick Reference Cheat Sheet]]

---

## Overview

### Why Enumeration Matters

Enumeration is the foundation of every red team engagement. It is not a phase you "complete" — it is a continuous loop of discovery, analysis, and refinement. The quality of your enumeration directly determines the quality of every subsequent action: exploitation, lateral movement, and persistence.

> **The 70% Rule**: Roughly 70% of the time in a competent red team engagement should be spent on enumeration and reconnaissance. Rushing to exploit is the number one mistake of junior operators. The veteran spends hours mapping the terrain before picking a single target.

### The Enumeration Mindset

1. **Be methodical** — Use checklists, not memory. Forgetting to check SNMP has cost operators critical access.
2. **Be paranoid** — Assume the target has more services, more hosts, more complexity than you can see.
3. **Be patient** — Slow, quiet scanning beats fast, loud scanning every time.
4. **Be recursive** — Every new finding is a new attack surface. Enumerate again.
5. **Document everything** — If it isn't written down, it didn't happen.

### The Two Worlds

| | External (Pre-Foothold) | Internal (Post-Foothold) |
|---|---|---|
| **Position** | Outside the perimeter | Inside the network |
| **Visibility** | Limited by firewalls, WAFs, CDN | Broad — direct network access |
| **Noise Profile** | High risk of detection by IDS/IPS | Lower risk, but still monitored |
| **Goal** | Find foothold entry points | Map the internal attack surface |
| **Speed** | Slower, stealthier | Can be faster but OPSEC still matters |

---

## External Enumeration (Pre-Foothold)

### DNS Reconnaissance

DNS is your first stop. It reveals subdomains, mail servers, infrastructure providers, and often forgotten/abandoned systems.

#### Zone Transfers

Always attempt zone transfers — they're rare but devastating when they work.

```bash
# Attempt AXFR against all discovered name servers
for ns in $(dig +short NS target.com); do
    dig axfr target.com @"$ns" 2>/dev/null
done
```

> ⚠️ **Warning**: Zone transfers are extremely loud and will almost certainly trigger alerts. Use only when stealth is not a priority or as a last resort.

#### Subdomain Discovery

```bash
# Passive — no direct interaction with the target
subfinder -d target.com -o subs_passive.txt

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u > crt_subs.txt

# DNS brute force (active — OPSEC consideration required)
amass enum -d target.com -o amass_subs.txt

# Fast brute force with resolved check
dnsx -l subs_passive.txt -r 1.1.1.1,8.8.8.8 -a -resp -o resolved_subs.txt
```

#### DNS Record Mining

```bash
# All record types
dig ANY target.com +noall +answer

# Specific high-value records
dig MX target.com +short      # Mail servers
dig TXT target.com +short     # SPF, DKIM, verification tokens
dig NS target.com +short      # Name servers
dig SRV _ldap._tcp.target.com # LDAP service records
```

### Port Scanning

#### Nmap — The Workhorse

```bash
# Top 1000 ports — fast sweep
nmap -sS -top-ports 1000 -oA sweep_top1k 10.0.0.0/24

# All ports — thorough but slow
nmap -sS -p- -T3 -oA full_scan 10.0.0.1

# Top ports with service version detection
nmap -sS -sV --top-ports 5000 -oA svc_scan 10.0.0.0/24

# UDP scan — often overlooked, high-value
nmap -sU --top-ports 100 -oA udp_top100 10.0.0.1
```

#### RustScan — Speed King

```bash
# Find all open ports fast, then nmap for detail
rustscan -a 10.0.0.0/24 --ulimit 5000 -t 2000 -- -sV -oA rustscan_detailed
```

#### Masscan — Internet-Scale

```bash
# Masscan for speed, output to nmap for service enum
# Method 1: List output → host list → nmap
masscan -p1-65535 10.0.0.0/24 --rate=10000 -oL masscan_out.txt
grep '^open' masscan_out.txt | awk '{print $4}' | sort -u > live_hosts.txt
nmap -sV -iL live_hosts.txt -oA masscan_nmap_detailed

# Method 2: XML output → NSE targets-xml script
masscan -p1-65535 10.0.0.0/24 --rate=10000 -oX masscan.xml
nmap --script targets-xml --script-arg newtargets --script-arg xmlfile=masscan.xml -sV -oA masscan_nmap_detailed
```

### Service Banner Grabbing

```bash
# Quick banner grab on common ports
nmap -sV --version-intensity 5 -p 21,22,25,80,110,143,443,445,993,995,3306,3389,8080 10.0.0.1

# Netcat banner grab
for port in 21 22 25 80 110 143 443 445; do
    echo -e "\n--- Port $port ---"
    echo "QUIT" | nc -w 3 10.0.0.1 "$port" 2>/dev/null
done

# OpenSSL for TLS services
echo | openssl s_client -connect 10.0.0.1:443 -servername target.com 2>/dev/null | openssl x509 -noout -text
```

> 💡 **Tip**: Certificate Subject Alternative Names (SANs) often reveal internal hostnames, admin panels, and staging environments.

### Web Technology Fingerprinting

```bash
# Wappalyzer-style fingerprinting
whatweb https://target.com

# WAF detection
wafw00f https://target.com

# HTTP header analysis
curl -sI https://target.com | head -30
```

---

## Internal Enumeration (Post-Foothold)

Once you have a foothold inside the network, the enumeration game changes entirely. You now have direct L2/L3 access and can see far more than you could from the outside.

### Host Discovery

```bash
# ARP scan — discovers hosts on the local segment
sudo arp-scan --interface=eth0 --localnet

# Ping sweep with nmap (caution: ICMP may be blocked)
nmap -sn -PE 10.0.0.0/24 -oA ping_sweep

# ARP-based host discovery (no ICMP, stealthier)
nmap -sn -PR 10.0.0.0/24 -oA arp_sweep

# Fast host discovery — no port scanning
nmap -sn -n --disable-arp-ping 10.0.0.0/24 -oA host_discovery
```

### ARP Scanning

```bash
# Native Linux ARP
ip neigh show | grep -v FAILED

# arp-scan — the gold standard
sudo arp-scan -I eth0 -l

# Netdiscover — passive + active
sudo netdiscover -r 10.0.0.0/24

# Passive ARP — zero noise
sudo tcpdump -i eth0 -n arp
```

> ⚠️ **Warning**: Active ARP scanning broadcasts to the entire segment. On a monitored network, this will be detected. Prefer passive ARP collection first.

### Service Enumeration (Internal)

```bash
# Quick internal service sweep
nmap -sS -sV -top-ports 1000 --open -oA int_svc 10.0.0.0/24

# Targeted: internal Windows environment
nmap -sS -sV -p 88,135,139,389,445,636,1433,3389,5985,5986,9389 --open -oA int_windows 10.0.0.0/24

# Targeted: internal Linux environment
nmap -sS -sV -p 21,22,80,111,443,2049,3306,5432,6379,8080,8443 --open -oA int_linux 10.0.0.0/24
```

### OS Fingerprinting

```bash
# Aggressive OS detection
nmap -O --osscan-guess 10.0.0.1

# Passive OS fingerprinting via p0f
sudo p0f -i eth0

# TTL-based OS guessing (quick and dirty)
ping -c 1 10.0.0.1 | grep ttl
# TTL ~64 → Linux | TTL ~128 → Windows | TTL ~255 → Network device
```

### Living Off the Land — Internal Recon Without Tools

When you can't upload tools, use what's already there:

```bash
# Windows — PowerShell
# Net view
net view /domain
net view /domain:CORP
net view \\COMPUTERNAME

# WMI queries
wmic computersystem list full
wmic ntelement get caption,version
wmic share get name,path

# ARP table
arp -a

# DNS lookup
nslookup -type=any target.com
nltest /dclist:CORP

# Linux
# Check hosts file
cat /etc/hosts

# ARP cache
ip neigh show
cat /proc/net/arp

# Network connections
ss -tlnp
netstat -tlnp

# Running services
systemctl list-units --type=service --state=running
```

---

### Enumeration from a Sliver C2 Implant

When you have a Sliver implant on a target, you can perform network reconnaissance directly from the compromised host — no need to upload additional tools.

```sliver
# Basic host recon
use <session-id>
whoami
getuid
getpid
ps
ifconfig
netstat

# Discover other hosts on the segment
shell arp -a                    # Windows ARP cache
shell ip neigh show             # Linux ARP cache
shell net view                  # Windows — discover hosts/shares
shell nltest /dclist:CORP       # Windows — list domain controllers

# Port scan from the implant (no nmap needed)
shell for /L %i in (1,1,254) do @ping -n 1 -w 100 10.0.0.%i > nul && echo 10.0.0.%i  # Windows ping sweep
shell for i in $(seq 1 254); do ping -c 1 -W 1 10.0.0.$i && echo 10.0.0.$i; done  # Linux ping sweep

# Service banner grab from implant
shell nc -zv 10.0.0.1 21-25,80,443,445,3389 2>&1 | grep succeeded

# Windows: enumerate shares, users, sessions
shell net share
shell net user
shell net localgroup administrators
shell net session

# Windows: PowerShell recon (no file drop)
shell powershell -c "Get-NetAdapter | Select Name,Status,LinkSpeed"
shell powershell -c "Get-NetTCPConnection | Where State -eq Listen | Select LocalAddress,LocalPort"
shell powershell -c "Get-Process | Select Name,Id,Path | Sort Name"

# Linux: enumerate network and services
shell ss -tlnp
shell cat /etc/hosts
shell find /etc -name "*.conf" -type f 2>/dev/null | head -20

# Upload tools for deeper enum (if needed)
upload /opt/linpeas.sh /tmp/linpeas.sh
shell chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh

# Pivot through implant for internal scanning
socks5 --bind 127.0.0.1:1080
# Then from operator machine:
# proxychains nmap -sT -p 22,80,443,445,3389 10.0.0.0/24
```

> [!tip] Sliver Advantage
> Running recon from the implant is stealthier than scanning from your attack box — the traffic originates from an internal host and blends with normal network activity. Use `shell` for quick checks and `upload` + `execute` for deeper enumeration tools.

---

## Protocol-Specific Deep Dives

### SMB (Ports 139, 445)

SMB is one of the richest attack surfaces in Windows environments. Never skip it.

#### enum4linux

```bash
# Full enumeration
enum4linux -a 10.0.0.1

# Specific checks
enum4linux -U 10.0.0.1    # Users
enum4linux -S 10.0.0.1    # Shares
enum4linux -G 10.0.0.1    # Groups
enum4linux -P 10.0.0.1    # Password policy
```

#### smbclient

```bash
# List shares — null session
smbclient -L //10.0.0.1 -N

# List shares — with credentials
smbclient -L //10.0.0.1 -U 'CORP\user%pass'

# Connect to a share
smbclient //10.0.0.1/C$ -U 'CORP\Admin%pass'

# Download files recursively
smbclient //10.0.0.1/share -U 'user%pass' -c "recurse ON; prompt OFF; mget *"
```

#### rpcclient

```bash
# Null session connection
rpcclient -U "" -N 10.0.0.1

# Once connected:
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> queryuser 0x1f4
rpcclient $> lookupnames admin
rpcclient $> enumprivs
rpcclient $> srvinfo
```

> 💡 **Tip**: Null sessions (anonymous SMB connections) still work on misconfigured systems. Always try `-N` (no password) first.

#### CrackMapExec / NetExec (nxc)

> [!info] Tool Update
> **CrackMapExec (CME)** was forked and renamed to **NetExec (`nxc`)** in 2023+. The original repository is no longer maintained. Kali now ships `netexec` as the primary package. The `crackmapexec` command still works as a backwards-compatible alias, but `nxc` is the recommended invocation.

```bash
# SMB enumeration
nxc smb 10.0.0.0/24 -u '' -p ''

# With credentials
nxc smb 10.0.0.0/24 -u 'user' -p 'pass' --shares
nxc smb 10.0.0.0/24 -u 'user' -p 'pass' --users
nxc smb 10.0.0.0/24 -u 'user' -p 'pass' --groups
nxc smb 10.0.0.0/24 -u 'user' -p 'pass' --pass-pol

# Session check
nxc smb 10.0.0.1 -u 'user' -p 'pass' --sessions
```

### LDAP (Ports 389, 636)

LDAP is the directory service backbone of Active Directory. It's a goldmine.

#### ldapsearch

```bash
# Base tree info
ldapsearch -x -H ldap://10.0.0.1 -b "" -s base namingcontexts

# Full domain dump — null bind
ldapsearch -x -H ldap://10.0.0.1 -b "DC=corp,DC=local" -LLL

# With credentials
ldapsearch -x -H ldap://10.0.0.1 -D "CORP\user" -w 'pass' -b "DC=corp,DC=local"

# Targeted queries
ldapsearch -x -H ldap://10.0.0.1 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
ldapsearch -x -H ldap://10.0.0.1 -b "DC=corp,DC=local" "(objectClass=group)" cn
ldapsearch -x -H ldap://10.0.0.1 -b "DC=corp,DC=local" "(objectClass=computer)" dnSHostname

# SPN enumeration (Kerberoast prep)
ldapsearch -x -H ldap://10.0.0.1 -b "DC=corp,DC=local" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# AS-REP roastable accounts (no pre-auth required)
ldapsearch -x -H ldap://10.0.0.1 -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

#### BloodHound

```bash
# Collect data with SharpHound (from Windows foothold)
SharpHound.exe -c All -d corp.local --zipfilename bh_data.zip

# Or use bloodhound-python (from Linux)
bloodhound-python -d corp.local -u user -p pass -ns 10.0.0.1 -c All

# Import the ZIP into BloodHound GUI
# Analyze: Shortest path to Domain Admins, Kerberoastable accounts, etc.
```

> 💡 **Tip**: BloodHound data is only as good as your collection. Run SharpHound from multiple contexts (different user privileges) to maximize edge collection.

### DNS (Port 53)

#### dnsenum

```bash
# Full enumeration
dnsenum target.com

# With zone transfer attempt and brute force
dnsenum -f /usr/share/wordlists/dns.txt target.com
```

#### dnsrecon

```bash
# Standard enumeration
dnsrecon -d target.com

# Zone transfer
dnsrecon -d target.com -t axfr

# Brute force subdomains
dnsrecon -d target.com -t brt -D /usr/share/wordlists/dns.txt

# Reverse lookup (PTR) on a range
dnsrecon -t rvs -i 10.0.0.0/24

# Cache snooping
dnsrecon -t snoop -n 10.0.0.1 -D /usr/share/wordlists/dns.txt
```

#### Internal DNS — Critical Post-Foothold

```bash
# AD DNS zones often reveal internal naming conventions
dig +short AXFR corp.local @10.0.0.1

# Global catalog
dig SRV _gc._tcp.corp.local @10.0.0.1

# Kerberos
dig SRV _kerberos._tcp.corp.local @10.0.0.1

# LDAP
dig SRV _ldap._tcp.corp.local @10.0.0.1
```

### SNMP (Ports 161, 162)

SNMP is frequently overlooked and often misconfigured with default community strings.

#### snmpwalk

```bash
# Walk with default community string 'public'
snmpwalk -v2c -c public 10.0.0.1

# System information
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.1

# Running processes
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.25.4.2

# Installed software
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.25.6.3

# Network interfaces
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.2.2

# Routing table
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.4.24

# User accounts (Windows)
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.4.1.77.1.2.25

# Share information (Windows)
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.4.1.77.1.2.3
```

#### onesixtyone — Fast SNMP Community String Brute Force

```bash
# Single host, common strings
onesixtyone -c /usr/share/wordlists/snmp_communities.txt 10.0.0.1

# Subnet sweep
onesixtyone -c /usr/share/wordlists/snmp_communities.txt -i targets.txt
```

> ⚠️ **Warning**: SNMP community string brute forcing is extremely noisy. Many IDS/IPS systems flag it immediately. Use only when stealth is not required.

#### SNMPv3 Enumeration

```bash
# Enumerate SNMPv3 usernames
snmpwalk -v3 -l authNoPriv -u noAuthUser 10.0.0.1

# With authentication
snmpwalk -v3 -l authPriv -u admin -A "password" -a MD5 -X "privpass" -x DES 10.0.0.1
```

### HTTP/HTTPS (Ports 80, 443, 8080, 8443)

#### gobuster — Directory & File Brute Forcing

```bash
# Directory enumeration
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -t 50 -o gobuster_dirs.txt

# With extensions
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,jsp,txt,bak -t 50

# Vhost enumeration
gobuster vhost -u https://target.com -w /usr/share/wordlists/subdomains.txt -t 50

# DNS subdomain enumeration
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt -t 50
```

#### nikto — Web Server Vulnerability Scanner

```bash
# Full scan
nikto -h https://target.com -output nikto_results.html -Format htm

# Specific checks
nikto -h https://target.com -Tuning 1234  # Only specific test categories
# 1 = Interesting file, 2 = Misconfiguration, 3 = Info disclosure, 4 = XSS/Injection

# Through proxy
nikto -h https://target.com -useproxy http://127.0.0.1:8080
```

#### ffuf — Fast Web Fuzzer

```bash
# Directory brute force
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 100 -o ffuf_dirs.json

# Subdomain enumeration (vhost)
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w /usr/share/wordlists/subdomains.txt -t 100

# Parameter fuzzing
ffuf -u https://target.com/api/?FUZZ=test -w /usr/share/wordlists/params.txt -t 50

# Recursive scanning
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -recursion -recursion-depth 2
```

> 💡 **Tip**: Filter out false positives by calibrating against a known 404. `ffuf -fc 404 -fs 1234 -mc 200,301,302`

### SSH (Port 22)

#### ssh-audit

```bash
# Full SSH configuration audit
ssh-audit target.com

# With verbose output
ssh-audit -v target.com

# Check specific algorithms
ssh-audit --list-algos target.com
```

#### Manual SSH Fingerprinting

```bash
# Banner grab
nc -w 3 10.0.0.1 22

# Key fingerprint
ssh-keyscan -t rsa,ecdsa,ed25519 10.0.0.1 2>/dev/null | ssh-keygen -lf -

# Supported auth methods
ssh -v -o PreferredAuthentications=none -o PubkeyAuthentication=no user@10.0.0.1 2>&1 | grep "Authenticated by"
```

### RDP (Port 3389)

```bash
# Nmap RDP scripts
nmap -sV -p 3389 --script=rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020 10.0.0.1

# Credentialed RDP check
nxc rdp 10.0.0.0/24 -u 'user' -p 'pass'

# xfreerdp banner
xfreerdp /v:10.0.0.1 /cert:ignore +auth-only

# Check for NLA requirement
nmap -p 3389 --script rdp-enum-encryption 10.0.0.1
```

---

## Network Mapping & Topology Discovery

### Layer 2 — Local Segment

```bash
# ARP table
arp -a
ip neigh show

# Full ARP scan
sudo arp-scan -I eth0 -l

# MAC vendor lookup
macchanger -l | grep -i "00:50:56"  # VMware
```

### Layer 3 — Routing

```bash
# Routing table
route -n
ip route show

# Traceroute (TCP for firewall evasion)
traceroute -T -p 80 10.0.0.1

# MTR — continuous traceroute
mtr -n -T -c 10 10.0.0.1
```

### Firewall & ACL Discovery

```bash
# TCP ACK scan to map firewall rules
nmap -sA -p 80,443,445,3389 10.0.0.1

# Identify filtered vs closed ports
nmap -sS -p- --open --defeat-rst-ratelimit 10.0.0.1

# Fragment packets to test firewall handling
nmap -sS -f -p 80,443,445 10.0.0.1
```

### Active Directory Topology

```bash
# Domain trust mapping
nltest /domain_trusts
nltest /dclist:corp.local

# Site and subnet information
ldapsearch -x -H ldap://10.0.0.1 -b "CN=Sites,CN=Configuration,DC=corp,DC=local" "(objectClass=site)" cn description

# Replication partners
repadmin /showrepl

# FSMO role holders
netdom query fsmo
```

### Network Device Discovery

```bash
# CDP (Cisco Discovery Protocol) — requires Cisco device
tcpdump -i eth0 -nn -c 50 cdp

# LLDP (Link Layer Discovery Protocol)
tcpdump -i eth0 -nn -c 50 ether proto 0x88cc

# SNMP-based device identification
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.1.1  # sysDescr
snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.1.2  # sysObjectID
```

---

## Automation — Bash One-Liners & Python Scripts

### Bash One-Liners

```bash
# Extract live hosts from nmap grepable output
awk '/Up$/{print $2}' scan.gnmap | sort -u > live_hosts.txt

# Quick port sweep across a subnet
for i in $(seq 1 254); do (echo >/dev/tcp/10.0.0.$i/445) 2>/dev/null && echo "10.0.0.$i:445 OPEN" & done; wait

# Reverse DNS sweep
for i in $(seq 1 254); do
    host 10.0.0.$i 2>/dev/null | grep "domain name" | cut -d' ' -f5 &
done | sort -u

# Extract all HTTP titles from a list of URLs
while read url; do
    title=$(curl -sk -m 5 "$url" 2>/dev/null | grep -oP '(?<=<title>).*?(?=</title>)')
    echo "$url — $title"
done < urls.txt

# Mass SMB null session check
while read ip; do
    smbclient -L "//$ip" -N 2>/dev/null | head -1 && echo "$ip: NULL SESSION OK"
done < live_hosts.txt

# Find all .bak files on an SMB share
smbclient //10.0.0.1/share -N -c "ls" 2>/dev/null | grep -i ".bak"

# Quick Kerberos pre-auth check (AS-REP roastable)
# Modern Kali uses impacket- prefixed commands
for user in $(cat users.txt); do
    impacket-GetNPUsers "corp.local/$user" -no-pass -dc-ip 10.0.0.1 2>/dev/null | grep -v "not found"
done

# Alternative: manual install path (if not using Kali repos)
# python3 /opt/impacket/GetNPUsers.py "corp.local/$user" -no-pass -dc-ip 10.0.0.1
```

### Python — Network Sweep Script

```python
#!/usr/bin/env python3
"""Network sweep: discover hosts and open ports on a subnet."""

import subprocess
import ipaddress
import argparse
import json
import concurrent.futures
from datetime import datetime

def nmap_sweep(subnet: str, ports: str = "22,80,443,445,3389,8080", threads: int = 10) -> dict:
    """Run nmap sweep across a subnet with service detection."""
    timestamp = datetime.now().isoformat()
    targets = [str(ip) for ip in ipaddress.ip_network(subnet, strict=False).hosts()]

    results = {}

    def scan_host(ip: str) -> dict:
        cmd = [
            "nmap", "-sS", "-sV", "--open", "-p", ports,
            "-T4", "--min-rate", "1000",
            "-oX", "-", ip
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"ip": ip, "raw": proc.stdout, "status": "success"}
        except subprocess.TimeoutExpired:
            return {"ip": ip, "raw": "", "status": "timeout"}
        except Exception as e:
            return {"ip": ip, "raw": "", "status": f"error: {e}"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_host, t): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            if r["status"] == "success" and "open" in r["raw"].lower():
                results[r["ip"]] = r["raw"]

    output = {
        "timestamp": timestamp,
        "subnet": subnet,
        "ports": ports,
        "hosts_found": len(results),
        "results": results
    }

    outfile = f"sweep_{subnet.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[+] Sweep complete: {len(results)} hosts found → {outfile}")
    return output

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network sweep tool")
    parser.add_argument("subnet", help="Target subnet (e.g., 10.0.0.0/24)")
    parser.add_argument("-p", "--ports", default="22,80,443,445,3389,8080",
                        help="Comma-separated port list")
    parser.add_argument("-t", "--threads", type=int, default=10,
                        help="Concurrent scan threads")
    args = parser.parse_args()
    nmap_sweep(args.subnet, args.ports, args.threads)
```

### Python — LDAP Enumerator

```python
#!/usr/bin/env python3
"""Lightweight LDAP enumerator for Active Directory environments."""

import subprocess
import argparse
import re
from collections import defaultdict

def ldap_enum(dc_ip: str, domain: str, username: str = "", password: str = "") -> dict:
    """Enumerate users, groups, computers, and SPNs from LDAP."""
    base_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    auth_args = []
    if username and password:
        auth_args = ["-D", f"{domain}\\{username}", "-w", password]

    results = defaultdict(list)

    queries = {
        "users": "(objectClass=user)",
        "groups": "(objectClass=group)",
        "computers": "(objectClass=computer)",
        "spns": "(servicePrincipalName=*)",
        "asrep_roastable": "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        "admin_count_1": "(&(objectClass=user)(adminCount=1))",
        "delegations": "(&(objectClass=user)(msds-allowedtodelegateto=*))",
    }

    for name, filt in queries.items():
        cmd = [
            "ldapsearch", "-x", "-H", f"ldap://{dc_ip}",
            "-b", base_dn, filt, "sAMAccountName", "servicePrincipalName", "memberOf"
        ] + auth_args

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            entries = proc.stdout.split("dn: ")
            for entry in entries[1:]:  # skip preamble
                sam = re.search(r"sAMAccountName:\s*(\S+)", entry)
                if sam:
                    results[name].append(sam.group(1))
        except Exception as e:
            print(f"[!] Error querying {name}: {e}")

    for category, items in results.items():
        print(f"\n[+] {category.upper()} ({len(items)} found):")
        for item in items[:20]:
            print(f"    {item}")
        if len(items) > 20:
            print(f"    ... and {len(items) - 20} more")

    return dict(results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LDAP enumerator")
    parser.add_argument("dc_ip", help="Domain controller IP")
    parser.add_argument("domain", help="Domain name (e.g., corp.local)")
    parser.add_argument("-u", "--username", default="", help="Username")
    parser.add_argument("-p", "--password", default="", help="Password")
    args = parser.parse_args()
    ldap_enum(args.dc_ip, args.domain, args.username, args.password)
```

### Python — SNMP Bulk Walker

```python
#!/usr/bin/env python3
"""Bulk SNMP walk across multiple hosts for key OIDs."""

import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

KEY_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "processes": "1.3.6.1.2.1.25.4.2",
    "software": "1.3.6.1.2.1.25.6.3",
    "interfaces": "1.3.6.1.2.1.2.2",
    "routing": "1.3.6.1.2.1.4.24",
    "users": "1.3.6.1.4.1.77.1.2.25",
    "shares": "1.3.6.1.4.1.77.1.2.3",
}

def snmp_walk(ip: str, community: str = "public", version: str = "2c") -> dict:
    """Walk key OIDs on a single host."""
    results = {"ip": ip, "data": {}}
    for name, oid in KEY_OIDS.items():
        cmd = ["snmpwalk", f"-v{version}", "-c", community, ip, oid]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and "No more variables" not in proc.stdout:
                results["data"][name] = proc.stdout.strip()
        except subprocess.TimeoutExpired:
            results["data"][name] = "TIMEOUT"
        except Exception as e:
            results["data"][name] = f"ERROR: {e}"
    return results

def bulk_walk(hosts_file: str, community: str = "public", threads: int = 5):
    """Walk multiple hosts from a file."""
    with open(hosts_file) as f:
        hosts = [line.strip() for line in f if line.strip()]

    print(f"[*] Walking {len(hosts)} hosts with community '{community}'...")
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(snmp_walk, ip, community) for ip in hosts]
        for future in futures:
            r = future.result()
            if r["data"]:
                results.append(r)
                sysname = r["data"].get("sysName", "unknown")
                print(f"[+] {r['ip']} — {sysname[:50]}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = f"snmp_bulk_{timestamp}.txt"
    with open(outfile, "w") as f:
        for r in results:
            f.write(f"\n{'='*60}\n{r['ip']}\n{'='*60}\n")
            for k, v in r["data"].items():
                f.write(f"\n--- {k} ---\n{v}\n")

    print(f"\n[+] Done. {len(results)} hosts responded → {outfile}")

if __name__ == "__main__":
    import sys
    parser = argparse.ArgumentParser(description="SNMP bulk walker")
    parser.add_argument("hosts_file", help="File with one IP per line")
    parser.add_argument("-c", "--community", default="public")
    parser.add_argument("-t", "--threads", type=int, default=5)
    args = parser.parse_args()
    bulk_walk(args.hosts_file, args.community, args.threads)
```

---

## Tool Comparison Table

| Feature | nmap | masscan | rustscan |
|---|---|---|---|
| **Speed** | Moderate | Extremely fast | Very fast |
| **Accuracy** | High | Moderate (false positives) | High (uses nmap for detail) |
| **Service Detection** | ✅ Full (`-sV`) | ❌ Basic only | ✅ Via nmap passthrough |
| **OS Fingerprinting** | ✅ (`-O`) | ❌ | ✅ Via nmap passthrough |
| **NSE Scripts** | ✅ 600+ scripts | ❌ | ✅ Via nmap passthrough |
| **UDP Scanning** | ✅ | ✅ | ❌ |
| **Stealth Options** | ✅ Timing, fragments, decoys | ❌ Very loud | ⚠️ Limited |
| **Rate Control** | `--min-rate` / `--max-rate` | `--rate` | `--ulimit`, `-t` |
| **Output Formats** | XML, grepable, normal, JSON | XML, list, binary | Via nmap |
| **IPv6** | ✅ | ❌ | ✅ |
| **Scan Techniques** | SYN, ACK, FIN, Xmas, Maimon, etc. | SYN only | SYN via nmap |
| **Best For** | Thorough, detailed scans | Internet-scale, large ranges | Fast port discovery + nmap detail |
| **OPSEC** | ✅ Good with tuning | ❌ Extremely noisy | ⚠️ Use with caution |

### Recommended Workflow

```
1. rustscan → Find open ports fast
2. nmap -sV -sC → Deep service enumeration on found ports
3. masscan → Only for /16+ ranges where speed is critical
```

---

## OPSEC — Stealth Scanning, Timing, IDS Evasion

### Nmap Timing Templates

| Template | Flag | Speed | Stealth | Use Case |
|---|---|---|---|---|
| Paranoid | `-T0` | 5 min/host | Maximum | IDS evasion, slow & quiet |
| Sneaky | `-T1` | 15 sec/host | High | Careful evasion |
| Polite | `-T2` | 0.7 sec/host | Moderate | Polite to target, less noise |
| Normal | `-T3` | Default | Default | Default, balanced |
| Aggressive | `-T4` | Fast | Low | Internal, time-sensitive |
| Insane | `-T5` | Very fast | None | Lab only, tons of noise |

### Evasion Techniques

```bash
# Fragment packets — split TCP header across packets
nmap -sS -f -p 80,443,445 10.0.0.1

# Double fragment
nmap -sS -ff -p 80,443,445 10.0.0.1

# Decoy scan — mix your IP with fake sources
nmap -sS -D RND:10 -p 80,443,445 10.0.0.1

# Specific decoys
nmap -sS -D 10.0.0.100,10.0.0.101,ME -p 80,443,445 10.0.0.1

# Idle scan — bounce off a zombie host
nmap -sI zombie_host:80 10.0.0.1

# Source port manipulation — use common allowed ports
nmap -sS --source-port 53 -p 80,443,445 10.0.0.1
nmap -sS --source-port 88 -p 445 10.0.0.1

# Randomize host order
nmap -sS --randomize-hosts -p 445 10.0.0.0/24

# MAC address spoofing
nmap -sS --spoof-mac 00:50:56:XX:XX:XX -p 445 10.0.0.1

# Data length — pad packets to unusual sizes
nmap -sS --data-length 64 -p 80,443 10.0.0.1

# Timing fine-tuning
nmap -sS -T2 --max-retries 1 --host-timeout 30m --scan-delay 5s -p 445 10.0.0.0/24
```

### IDS/IPS Evasion Strategy

> ⚠️ **Warning**: No technique guarantees evasion. Modern IDS/IPS systems correlate across time and patterns. The goal is to raise the cost of detection, not eliminate it.

1. **Slow down** — Time is your ally. `-T0` or `-T1` for critical targets.
2. **Distribute** — Scan from multiple sources over extended time periods.
3. **Blend in** — Use source ports that match expected traffic (53 for DNS, 80/443 for HTTP).
4. **Fragment** — Split probe packets to bypass simple signature matching.
5. **Decoys** — Add noise so your real IP is one of many in the logs.
6. **Target wisely** — Don't scan everything. Enumerate surgically based on prior findings.
7. **Time your scans** — Scan during high-traffic periods (business hours) to blend with noise.

### Detecting Your Own Noise

```bash
# Monitor your own scan traffic
tcpdump -i eth0 -nn 'src host YOUR_IP and (tcp[tcpflags] & (tcp-syn) != 0)'

# Count packets per second
tcpdump -i eth0 -nn -c 1000 'src host YOUR_IP' 2>&1 | tail -1
```

---

## Decision Framework — If You Find X, Try Y

| Finding | Next Step | Tool / Command |
|---|---|---|
| **Port 53 open** | DNS zone transfer, subdomain brute | `dig axfr`, `dnsrecon`, `dnsenum` |
| **Port 80/443 open** | Web tech fingerprint, dir brute | `whatweb`, `gobuster`, `ffuf`, `nikto` |
| **Port 139/445 open** | Null session, share enum, user enum | `enum4linux`, `smbclient`, `rpcclient` |
| **Port 161 open (SNMP)** | Community string brute, full walk | `onesixtyone`, `snmpwalk` |
| **Port 389/636 open** | LDAP dump, BloodHound collection | `ldapsearch`, `bloodhound-python` |
| **Port 88 open (Kerberos)** | User enum, AS-REP roast, Kerberoast | `kerbrute`, `GetNPUsers`, `GetUserSPNs` |
| **Port 1433 open (MSSQL)** | Default creds, SQL auth brute | `nxc mssql`, `mssqlclient.py` |
| **Port 3306 open (MySQL)** | Default creds, auth bypass | `mysql -u root`, `nmap --script mysql-vuln*` |
| **Port 3389 open (RDP)** | Auth check, NLA status | `nxc rdp`, `nmap --script rdp-*` |
| **Port 22 open (SSH)** | Key fingerprint, auth methods | `ssh-audit`, `ssh-keyscan` |
| **Port 25 open (SMTP)** | User enum, open relay | `smtp-user-enum`, `nmap --script smtp-*` |
| **Port 5985/5986 (WinRM)** | Auth check, shell access | `nxc winrm`, `evil-winrm` |
| **Null SMB session** | Full share/user/group enum | `enum4linux -a`, `rpcclient` |
| **SNMP community string** | Full MIB walk, process list, software | `snmpwalk -c <string>` |
| **Writable SMB share** | Search for creds, configs, scripts | `smbclient`, mount and `find` |
| **Domain joined host** | AD enumeration, BloodHound | `ldapsearch`, `SharpHound`, `BloodHound` |
| **SSL certificate** | Extract SANs, issuer, validity | `openssl s_client`, `curl -sk` |
| **Web login form** | Default creds, SQLi, brute force | `hydra`, `burp`, `sqlmap` |
| **API endpoint** | Swagger/OpenAPI doc, fuzz params | `ffuf`, `burp`, manual review |
| **FTP anonymous login** | Download everything, check for creds | `wget -r ftp://10.0.0.1/` |
| **Redis (6379) unauth** | Dump keys, check for creds in values | `redis-cli -h 10.0.0.1 INFO` |
| **MongoDB (27017) unauth** | List databases, dump collections | `mongo --host 10.0.0.1 --eval "db.adminCommand('listDatabases')"` |

---

## Quick Reference Cheat Sheet

### Host Discovery

```bash
# ARP
arp-scan -l -I eth0
ip neigh show

# ICMP
nmap -sn 10.0.0.0/24

# TCP
nmap -sn -PS80,443,445 10.0.0.0/24
```

### Port Scanning

```bash
# SYN scan — default, reliable
nmap -sS -p- -T4 --open 10.0.0.1

# Fast sweep
rustscan -a 10.0.0.0/24 -- -sV

# UDP top ports
nmap -sU --top-ports 50 --open 10.0.0.1
```

### Service Enumeration

```bash
# SMB
enum4linux -a 10.0.0.1
smbclient -L //10.0.0.1 -N
rpcclient -U "" -N 10.0.0.1

# LDAP
ldapsearch -x -H ldap://10.0.0.1 -b "DC=corp,DC=local"
bloodhound-python -d corp.local -u user -p pass -ns 10.0.0.1

# SNMP
onesixtyone -c communities.txt 10.0.0.1
snmpwalk -v2c -c public 10.0.0.1

# DNS
dig axfr target.com @10.0.0.1
dnsrecon -d target.com

# HTTP
gobuster dir -u https://target.com -w common.txt -x php,asp
nikto -h https://target.com
ffuf -u https://target.com/FUZZ -w common.txt

# SSH
ssh-audit 10.0.0.1
nc -w 3 10.0.0.1 22
```

### Active Directory Quick Hits

```bash
# Domain info
nltest /dclist:corp.local
netdom query fsmo

# Kerberos
kerbrute userenum --dc 10.0.0.1 -d corp.local users.txt
impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip 10.0.0.1
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.1 -request

# BloodHound
SharpHound.exe -c All -d corp.local
bloodhound-python -d corp.local -u user -p pass -ns 10.0.0.1 -c All
```

### CrackMapExec / NetExec Cheat Sheet

> [!info] NetExec (`nxc`) is the successor to CrackMapExec. `crackmapexec` still works as an alias.

```bash
# SMB
nxc smb 10.0.0.0/24 -u '' -p ''          # Null session
nxc smb 10.0.0.0/24 -u user -p pass --shares
nxc smb 10.0.0.0/24 -u user -p pass --users
nxc smb 10.0.0.0/24 -u user -p pass --pass-pol
nxc smb 10.0.0.0/24 -u user -p pass --loggedon-users

# WinRM
nxc winrm 10.0.0.0/24 -u user -p pass

# MSSQL
nxc mssql 10.0.0.0/24 -u sa -p '' --query "SELECT name FROM sys.databases"

# SSH
nxc ssh 10.0.0.0/24 -u user -p pass

# RDP
nxc rdp 10.0.0.0/24 -u user -p pass
```

### OPSEC Quick Reference

| Goal | Command |
|---|---|
| Slow scan | `nmap -sS -T0 -p 445 10.0.0.1` |
| Fragmented | `nmap -sS -f -p 445 10.0.0.1` |
| Decoys | `nmap -sS -D RND:10 -p 445 10.0.0.1` |
| Source port | `nmap -sS --source-port 53 -p 445 10.0.0.1` |
| Idle scan | `nmap -sI zombie:80 10.0.0.1` |
| MAC spoof | `nmap -sS --spoof-mac 0 10.0.0.1` |
| Randomize | `nmap -sS --randomize-hosts 10.0.0.0/24` |

---

## Related Guides

- [[Red Team Engagement Guide]] — Full engagement methodology
- [[Sliver C2 - Red Team Operator Guide]] — C2 framework for post-exploitation

---

> *"The quieter you become, the more you are able to hear."*
>
> — Kali Linux

---

*Last updated: 2026-04-29 | Author: clawd 🦞*