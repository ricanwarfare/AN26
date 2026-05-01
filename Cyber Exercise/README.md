---
tags: [redteam, cyber-exercise, index, engagement, overview]
created: 2026-04-29
author: clawd
---

# 🎯 Cyber Exercise — Red Team Knowledge Base

> A curated collection of operational guides for authorized red team engagements, penetration testing, and adversary simulation.

---

## 📚 The Guides

| Guide | Purpose | When to Read |
|-------|---------|-------------|
| **[[Network Enumeration Guide]]** | Systematic reconnaissance and network mapping | **First** — before any engagement starts |
| **[[Red Team Engagement Guide]]** | Full engagement lifecycle from scoping to cleanup | After enum, for engagement structure |
| **[[Metasploit 101]]** | Exploitation framework for initial access and post-exploitation | When you need to exploit or automate post-exploitation |
| **[[Sliver C2 - Red Team Operator Guide]]** | Advanced C2 infrastructure, implants, and long-term operations | After initial foothold, for persistent C2 and evasion |
| **[[Evasion & Bypass Techniques]]** | AV/EDR evasion, AMSI bypass, process injection, OPSEC | Before deploying implants, when detection is a concern |
| **[[OS Exploit Reference]]** | CVE database by OS — Ubuntu, Windows 10/11/XP, Server 2008/2012 R2 | When you need to match a target OS to known exploits |
| **[[Security/CVEs/CVE-2026-31431 - Copy Fail|CVE-2026-31431 - Copy Fail]]** | Critical Linux kernel LPE — 732 bytes to root, all distros | When targeting Linux systems (especially unpatched kernels) |

---

## 🗺️ Engagement Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. ENUMERATION                                                  │
│     └─▶ [[Network Enumeration Guide]]                           │
│         • External recon (DNS, ports, services)                   │
│         • Internal mapping (post-foothold)                       │
│         • Protocol-specific deep dives                            │
├─────────────────────────────────────────────────────────────────┤
│  2. ENGAGEMENT PLANNING                                            │
│     └─▶ [[Red Team Engagement Guide]]                             │
│         • Scope, rules of engagement, OPSEC                      │
│         • Pre-engagement checklist                                 │
│         • Legal/authorization framework                            │
├─────────────────────────────────────────────────────────────────┤
│  3. INITIAL ACCESS / EXPLOITATION                                  │
│     └─▶ [[Metasploit 101]]                                        │
│         • CVE exploitation, payload generation                   │
│         • Rapid testing and validation                            │
│         • Database tracking and automation                        │
├─────────────────────────────────────────────────────────────────┤
│  4. C2 & PERSISTENCE                                               │
│     └─▶ [[Sliver C2 - Red Team Operator Guide]]                   │
│         • Implant generation and deployment                      │
│         • Multi-transport C2 (HTTP/S, DNS, WireGuard, mTLS)      │
│         • Long-term persistence and evasion                        │
├─────────────────────────────────────────────────────────────────┤
│  4b. EVASION & OPSEC                                               │
│     └─▶ [[Evasion & Bypass Techniques]]                           │
│         • AMSI bypass, EDR evasion, AV evasion                   │
│         • Process injection, memory-only execution                 │
│         • Sandbox detection, timestomping, log clearing            │
├─────────────────────────────────────────────────────────────────┤
│  4c. EXPLOIT REFERENCE                                             │
│     └─▶ [[OS Exploit Reference]] + [[Security/CVEs/CVE-2026-31431 - Copy Fail|CVE-2026-31431]] │
│         • Match target OS to known CVEs and exploits               │
│         • Linux kernel LPE (Copy Fail), Windows SMB, AD attacks    │
├─────────────────────────────────────────────────────────────────┤
│  5. POST-EXPLOITATION & LATERAL MOVEMENT                         │
│     └─▶ [[Red Team Engagement Guide]] + [[Metasploit 101]]       │
│         • Privilege escalation                                     │
│         • Credential harvesting                                     │
│         • Lateral movement and pivoting                           │
├─────────────────────────────────────────────────────────────────┤
│  6. REPORTING & CLEANUP                                            │
│     └─▶ [[Red Team Engagement Guide]]                             │
│         • Evidence collection and documentation                  │
│         • Remediation recommendations                             │
│         • Cleanup and artifact removal                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tool Coverage Matrix

| Phase | Primary Tools | Reference Guide |
|-------|--------------|-----------------|
| **External Recon** | nmap, masscan, dnsenum, gobuster, nikto | [[Network Enumeration Guide]] |
| **Internal Recon** | nmap, enum4linux, ldapsearch, snmpwalk, CrackMapExec | [[Network Enumeration Guide]] |
| **Exploitation** | msfconsole, msfvenom, exploit modules | [[Metasploit 101]] |
| **C2 Infrastructure** | Sliver server/client, listeners, implants | [[Sliver C2 - Red Team Operator Guide]] |
| **Post-Exploitation** | Meterpreter, post modules, resource scripts | [[Metasploit 101]] |
| **Persistence** | Sliver beacons, profiles, armory extensions | [[Sliver C2 - Red Team Operator Guide]] |
| **Lateral Movement** | PsExec, WMI, PowerShell remoting, Sliver pivot | [[Red Team Engagement Guide]] |
| **Evasion** | AMSI bypass, EDR unhooking, direct syscalls, packers | [[Evasion & Bypass Techniques]] |
| **Exploit Reference** | CVE matching by OS version, Metasploit modules | [[OS Exploit Reference]] |
| **Linux LPE** | CVE-2026-31431 (Copy Fail) — 732-byte kernel exploit | [[Security/CVEs/CVE-2026-31431 - Copy Fail|CVE-2026-31431 - Copy Fail]] |

---

## ⚡ Quick Start — First Time Here?

1. **Read** [[Network Enumeration Guide]] — master the recon process
2. **Skim** [[Red Team Engagement Guide]] — understand the engagement structure
3. **Practice** [[Metasploit 101]] — get comfortable with exploitation
4. **Study** [[Evasion & Bypass Techniques]] — learn to avoid detection
5. **Study** [[Sliver C2 - Red Team Operator Guide]] — learn C2 for advanced ops
6. **Reference** [[OS Exploit Reference]] — match targets to known CVEs
7. **Study** [[CVE-2026-31431 - Copy Fail|CVE-2026-31431 - Copy Fail]] — understand critical Linux kernel LPE

---

## 🏷️ Tags

#redteam #engagement #enumeration #metasploit #sliver #c2 #exploitation #recon #pentest #adversary-simulation

---

*Last updated: 2026-04-29*
