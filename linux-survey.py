#!/usr/bin/env python3
import os
import sys
import stat
import hashlib
import pwd
import grp
import time
import re
import json
import argparse
import subprocess
from dataclasses import dataclass, field

# Sensitive environment variable pattern for masking
SENSITIVE_ENV_PATTERNS = re.compile(
    r'(key|secret|password|passwd|token|credential|private|auth)',
    re.IGNORECASE
)


def safe_env_value(key, value):
    if SENSITIVE_ENV_PATTERNS.search(key):
        return f"{value[:4]}{'*' * 8}" if len(value) > 4 else "****"
    return value


# Configuration
@dataclass
class Config:
    output_file: str = 'survey_results.txt'
    output_format: str = 'text'
    skip_modules: list = field(default_factory=list)
    only_modules: list = field(default_factory=list)
    no_hash: bool = True  # Default: off (skip hashing for speed)
    log_depth: int = 300

config = Config()
OUTPUT_BUFFER = []
json_sections = {}
_process_names = {}

def report(msg, section_name=None):
    """Log a message to text buffer and optionally to JSON section."""
    print(msg)
    OUTPUT_BUFFER.append(msg + "\n")

def json_report(section, data_dict):
    """Add structured data to JSON output."""
    json_sections[section] = data_dict

def pad(s, length):
    s = str(s)
    return s + " " * (length - len(s))

def section(title):
    border = "################################################################################"
    report("\n" + border)
    report("#  " + title.upper())
    report(border + "\n")

def get_file_hash(path):
    try:
        if not os.path.exists(path): return "N/A"
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return "ERROR"

# TCP state hex codes from /proc/net/tcp
TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING',
}


def parse_proc_addr(addr):
    """Convert a hex IP:port address from /proc/net/tcp to human-readable form.

    Addresses in /proc/net/tcp are in hex format like 0100007F:0050
    (little-endian IP followed by big-endian port).
    """
    ip_hex, port_hex = addr.split(':')
    ip = ".".join([str(int(ip_hex[i:i+2], 16)) for i in range(len(ip_hex)-2, -1, -2)])
    port = str(int(port_hex, 16))
    return f"{ip}:{port}"


def parse_proc_addr_v6(addr):
    """Convert a hex IPv6:port address from /proc/net/tcp6 to human-readable form.

    IPv6 addresses in /proc/net/tcp6 are 32 hex chars (little-endian per 4-byte group)
    like 00000000000000000000000001000000:0050.
    Each 4-byte (8-char) group is byte-swapped internally.
    """
    ip_hex, port_hex = addr.split(':')
    port = str(int(port_hex, 16))

    # IPv6 is 32 hex chars; split into 8 groups of 4 hex chars
    # Each 4-char group (2 bytes) is stored little-endian, so swap within each group
    groups = []
    for i in range(0, len(ip_hex), 8):
        chunk = ip_hex[i:i+8]
        # Swap byte order within each 4-byte chunk: reverse pairs of 2 hex chars
        swapped = chunk[6:8] + chunk[4:6] + chunk[2:4] + chunk[0:2]
        groups.append(swapped)

    # Format as standard IPv6 colon-separated hextets
    hextets = []
    for g in groups:
        hextets.append(f"{int(g[0:4], 16):x}:{int(g[4:8], 16):x}")
    ip_str = ":".join(hextets)

    # Compress :: where possible (replace longest run of :0:0: with ::)
    # Simple approach: normalize consecutive :0: sequences
    parts = ip_str.split(':')
    # Find longest run of '0's
    best_start, best_len = -1, 0
    cur_start, cur_len = -1, 0
    for idx, p in enumerate(parts):
        if p == '0':
            if cur_start == -1:
                cur_start = idx
            cur_len += 1
            if cur_len > best_len:
                best_start = cur_start
                best_len = cur_len
        else:
            cur_start = -1
            cur_len = 0

    if best_len >= 2:
        if best_start == 0:
            compressed = '::' + ':'.join(parts[best_len:])
        elif best_start + best_len == len(parts):
            compressed = ':'.join(parts[:best_start]) + '::'
        else:
            compressed = ':'.join(parts[:best_start]) + '::' + ':'.join(parts[best_start + best_len:])
        ip_str = compressed
    else:
        ip_str = ':'.join(parts)

    return f"[{ip_str}]:{port}"


# --- Survey Modules ---

def survey_system_info():
    section("System Information")
    uname = os.uname()
    report("Host: " + uname.nodename)
    report("Kernel: " + uname.release)
    report("Version: " + uname.version)
    
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if "MemTotal" in line:
                    mem_str = line.split(":")[1].strip()
                    try:
                        kb = int(mem_str.split()[0])
                        mb = kb // 1024
                        report(f"Memory: {mb} MB")
                    except (ValueError, IndexError):
                        report(f"Memory: {mem_str}")
                    break
    except (PermissionError, FileNotFoundError, OSError):
        pass

    cpu_count = os.cpu_count()
    if cpu_count is not None:
        report("CPUs: " + str(cpu_count))

def survey_processes():
    if config.no_hash:
        section("Running Processes")
    else:
        section("Running Processes (with MD5)")

    if os.geteuid() != 0:
        # Check if hidepid is set (can't see other users' processes)
        try:
            with open("/proc/1/comm", "r") as f:
                pass  # Can see PID 1 — hidepid not active
        except PermissionError:
            report("[!] /proc is restricted (hidepid=2). Only current user's processes visible.")

    if config.no_hash:
        report(pad("PID", 8) + pad("PPID", 8) + pad("Name", 25) + "Cmdline")
        report(pad("---", 8) + pad("----", 8) + pad("----", 25) + "-------")
    else:
        report(pad("PID", 8) + pad("PPID", 8) + pad("Name", 25) + pad("MD5", 34) + "Cmdline")
        report(pad("---", 8) + pad("----", 8) + pad("----", 25) + pad("---", 34) + "-------")
    
    pids = [d for d in os.listdir('/proc') if d.isdigit()]
    for pid in sorted(pids, key=int):
        try:
            with open(f"/proc/{pid}/comm", "r", errors="replace") as f:
                name = f.read().strip()
            _process_names[pid] = name
            with open(f"/proc/{pid}/cmdline", "r", errors="replace") as f:
                # cmdline is null-terminated
                cmdline = f.read().replace('\0', ' ').strip()
            
            ppid = ""
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        ppid = line.split(":")[1].strip()
                        break

            # exe is a symlink, readlink to get path or hash directly
            exe_path = os.readlink(f"/proc/{pid}/exe")
            deleted = exe_path.endswith("(deleted)")
            deleted_flag = " [DELETED]" if deleted else ""

            if config.no_hash:
                report(pad(pid, 8) + pad(ppid, 8) + pad(name[:24], 25) + cmdline[:100] + deleted_flag)
            else:
                # To be stealthy, we hash the proc link directly
                file_hash = get_file_hash(f"/proc/{pid}/exe")
                report(pad(pid, 8) + pad(ppid, 8) + pad(name[:24], 25) + pad(file_hash, 34) + cmdline[:100] + deleted_flag)
        except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
            continue

def _parse_proc_net(proto_name, file_path, is_v6=False):
    """Helper to parse /proc/net/{tcp,udp,tcp6,udp6} files."""
    connections = []
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[1]
                remote = parts[2]
                state_hex = parts[3]
                parser = parse_proc_addr_v6 if is_v6 else parse_proc_addr
                local_str = parser(local)
                remote_str = parser(remote)
                state_name = TCP_STATES.get(state_hex, state_hex)
                connections.append((local_str, remote_str, state_name, state_hex))
    except (PermissionError, FileNotFoundError, OSError):
        pass
    return connections


def survey_network():
    section("Network Interfaces & IPs")
    try:
        output = subprocess.check_output(["ip", "-o", "addr", "show"], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
        if output.strip():
            for line in output.strip().split("\n"):
                report(f"  {re.sub(' +', ' ', line.strip())}")
        else:
            report("  (no interfaces found via ip command)")
    except (OSError, subprocess.CalledProcessError):
        try:
            output = subprocess.check_output(["ifconfig"], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
            for line in output.strip().split("\n"):
                if line.strip():
                    report(f"  {line.strip()}")
        except (OSError, subprocess.CalledProcessError):
            report("  (failed to get IP addresses via ip/ifconfig)")
            try:
                with open("/proc/net/dev", "r") as f:
                    for line in f.readlines()[2:]:
                        parts = line.split(":")
                        if len(parts) > 1:
                            report("  Interface: " + parts[0].strip())
            except (PermissionError, FileNotFoundError, OSError): pass

    section("Network Routes")
    try:
        output = subprocess.check_output(["ip", "route", "show"], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
        if output.strip():
            for line in output.strip().split("\n"):
                report(f"  {line.strip()}")
        else:
            report("  (no routes found)")
    except (OSError, subprocess.CalledProcessError):
        try:
            output = subprocess.check_output(["route", "-n"], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
            for line in output.strip().split("\n"):
                if line.strip():
                    report(f"  {line.strip()}")
        except (OSError, subprocess.CalledProcessError):
            report("  (failed to get routes)")

    section("DNS Configuration")
    if os.path.exists("/etc/resolv.conf"):
        report("  /etc/resolv.conf:")
        _print_file_contents("/etc/resolv.conf", prefix="    ")
    else:
        report("  /etc/resolv.conf not found")
        
    try:
        output = subprocess.check_output(["resolvectl", "status"], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
        if output.strip():
            report("  resolvectl status (DNS info):")
            for line in output.strip().split("\n"):
                if "DNS Server" in line or "DNS Domain" in line:
                    report(f"    {line.strip()}")
    except (OSError, subprocess.CalledProcessError):
        pass

    # --- TCP IPv4 ---
    section("Active TCP Connections (IPv4)")
    report(pad("Local Address", 25) + pad("Remote Address", 25) + "State")
    for local, remote, state, _ in _parse_proc_net("TCP", "/proc/net/tcp", is_v6=False):
        report(pad(local, 25) + pad(remote, 25) + state)

    # --- TCP IPv6 ---
    section("Active TCP Connections (IPv6)")
    report(pad("Local Address", 48) + pad("Remote Address", 48) + "State")
    tcp6_conns = _parse_proc_net("TCP6", "/proc/net/tcp6", is_v6=True)
    if tcp6_conns:
        for local, remote, state, _ in tcp6_conns:
            report(pad(local, 48) + pad(remote, 48) + state)
    else:
        report("  (no IPv6 TCP connections found or file not readable)")

    # --- UDP IPv4 ---
    section("Active UDP Connections (IPv4)")
    report(pad("Local Address", 25) + pad("Remote Address", 25) + "State")
    udp_conns = _parse_proc_net("UDP", "/proc/net/udp", is_v6=False)
    if udp_conns:
        for local, remote, state, shex in udp_conns:
            # UDP states are simpler; show hex state if not in TCP_STATES
            state_display = state if state != shex else shex
            report(pad(local, 25) + pad(remote, 25) + state_display)
    else:
        report("  (no IPv4 UDP connections found or file not readable)")

    # --- UDP IPv6 ---
    section("Active UDP Connections (IPv6)")
    report(pad("Local Address", 48) + pad("Remote Address", 48) + "State")
    udp6_conns = _parse_proc_net("UDP6", "/proc/net/udp6", is_v6=True)
    if udp6_conns:
        for local, remote, state, shex in udp6_conns:
            state_display = state if state != shex else shex
            report(pad(local, 48) + pad(remote, 48) + state_display)
    else:
        report("  (no IPv6 UDP connections found or file not readable)")

def survey_users():
    section("Users & Groups")
    report("Local Accounts (Enabled Shells):")
    for user in pwd.getpwall():
        if user.pw_shell not in ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"]:
            report(f"  {user.pw_name:<15} UID: {user.pw_uid:<5} Home: {user.pw_dir}")
    
    report("\nGroup Memberships (Sudo/Admin):")
    for group_name in ["sudo", "wheel", "admin"]:
        try:
            g = grp.getgrnam(group_name)
            report(f"  {group_name}: {', '.join(g.gr_mem)}")
        except KeyError:
            pass

def survey_services():
    section("Init System & Services")
    init_type = "Unknown"
    try:
        with open("/proc/1/comm", "r") as f:
            init_name = f.read().strip()
            if init_name == "systemd": init_type = "Systemd"
            elif init_name == "init": init_type = "SysVinit"
    except (PermissionError, FileNotFoundError, OSError): pass
    report("Init System: " + init_type)
    
    if init_type == "Systemd":
        report("  (Detailed systemd services listed in 'Systemd Services' module)")

def survey_firewall():
    section("Firewall Status")

    # iptables — check if kernel module is loaded
    if os.path.exists("/proc/net/ip_tables_names"):
        report("  iptables: kernel module loaded")
        try:
            with open("/proc/net/ip_tables_names", "r") as f:
                tables = [line.strip() for line in f if line.strip()]
            if tables:
                report(f"    Loaded Tables: {', '.join(tables)}")
                for table in tables:
                    report(f"    --- iptables rules for table: {table} ---")
                    try:
                        output = subprocess.check_output(
                            ["iptables-save", "-t", table],
                            stderr=subprocess.DEVNULL,
                            universal_newlines=True,
                            timeout=10
                        )
                        if output.strip():
                            for line in output.strip().split("\n"):
                                report(f"      {line}")
                        else:
                            report("      (no rules)")
                    except (OSError, subprocess.CalledProcessError):
                        report("      (failed to query rules)")
        except (PermissionError, FileNotFoundError, OSError):
            pass
    elif os.path.exists("/proc/net/ip_tables_targets"):
        report("  iptables: kernel module loaded (targets only)")
        try:
            with open("/proc/net/ip_tables_targets", "r") as f:
                targets = f.read().strip()
                if targets:
                    report(f"    Targets: {targets}")
        except (PermissionError, FileNotFoundError, OSError):
            pass
    else:
        report("  iptables: not active (module not loaded)")

    # nftables — check if active
    if os.path.exists("/proc/net/nf_tables_names"):
        report("  nftables: active")
        try:
            with open("/proc/net/nf_tables_names", "r") as f:
                names = f.read().strip()
                if names:
                    report(f"    Tables: {names}")
                    report("    --- nftables ruleset ---")
                    try:
                        output = subprocess.check_output(
                            ["nft", "list", "ruleset"],
                            stderr=subprocess.DEVNULL,
                            universal_newlines=True,
                            timeout=10
                        )
                        if output.strip():
                            for line in output.strip().split("\n"):
                                report(f"      {line}")
                        else:
                            report("      (no rules)")
                    except (OSError, subprocess.CalledProcessError):
                        report("      (failed to query nftables rules)")
        except (PermissionError, FileNotFoundError, OSError):
            pass
    else:
        report("  nftables: not active")

    # UFW — check config
    ufw_conf = "/etc/ufw/ufw.conf"
    if os.path.exists(ufw_conf):
        report("  UFW: installed")
        try:
            with open(ufw_conf, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("ENABLED="):
                        status = line.split("=", 1)[1] if "=" in line else "unknown"
                        report(f"    Status: {'enabled' if status == 'yes' else 'disabled'}")
                        break
        except (PermissionError, FileNotFoundError, OSError):
            report("    (could not read config)")
    else:
        report("  UFW: not installed")

    # firewalld — check config
    firewalld_conf = "/etc/firewalld/firewalld.conf"
    if os.path.exists(firewalld_conf):
        report("  firewalld: installed")
        try:
            with open(firewalld_conf, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("Enabled") or ("Enabled" in line and "=" in line):
                        report(f"    {line}")
        except (PermissionError, FileNotFoundError, OSError):
            report("    (could not read config)")
    else:
        report("  firewalld: not installed")


def _print_file_contents(filepath, prefix="    "):
    try:
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    report(f"{prefix}{stripped}")
    except (PermissionError, FileNotFoundError, OSError, UnicodeDecodeError):
        report(f"{prefix}(not readable or error)")


def survey_scheduled_tasks():
    section("Persistence & Scheduled Tasks")

    # /etc/crontab
    if os.path.exists("/etc/crontab"):
        report("  /etc/crontab:")
        _print_file_contents("/etc/crontab", prefix="    ")
    else:
        report("  /etc/crontab: not found")

    # /etc/anacrontab
    if os.path.exists("/etc/anacrontab"):
        report("  /etc/anacrontab:")
        _print_file_contents("/etc/anacrontab", prefix="    ")
    else:
        report("  /etc/anacrontab: not found")

    # /etc/cron.d/
    cron_d = "/etc/cron.d"
    if os.path.isdir(cron_d):
        try:
            entries = sorted(os.listdir(cron_d))
            if entries:
                report(f"  {cron_d}/:")
                for entry in entries:
                    report(f"    File: {entry}")
                    _print_file_contents(os.path.join(cron_d, entry), prefix="      ")
            else:
                report(f"  {cron_d}/: (empty)")
        except (PermissionError, FileNotFoundError, OSError):
            report(f"  {cron_d}/: (not readable)")
    else:
        report(f"  {cron_d}/: not found")

    # /var/spool/cron/crontabs/
    spool = "/var/spool/cron/crontabs"
    if os.path.isdir(spool):
        try:
            entries = sorted(os.listdir(spool))
            if entries:
                report(f"  {spool}/:")
                for entry in entries:
                    report(f"    User: {entry}")
                    _print_file_contents(os.path.join(spool, entry), prefix="      ")
            else:
                report(f"  {spool}/: (empty)")
        except (PermissionError, FileNotFoundError, OSError):
            report(f"  {spool}/: (not readable)")
    else:
        report(f"  {spool}/: not found or not accessible")

    # systemd timer units
    timer_dirs = ["/etc/systemd/system", "/lib/systemd/system"]
    found_timers = []
    for tdir in timer_dirs:
        if os.path.isdir(tdir):
            try:
                for fname in os.listdir(tdir):
                    if fname.endswith(".timer"):
                        found_timers.append((tdir, fname))
            except (PermissionError, FileNotFoundError, OSError):
                pass

    if found_timers:
        report("  Systemd Timer Units:")
        for tdir, fname in sorted(found_timers):
            report(f"    {tdir}/{fname}")
            _print_file_contents(os.path.join(tdir, fname), prefix="      ")
    else:
        report("  Systemd Timer Units: none found")


def survey_packages_detailed():
    section("Package Management (Detailed)")

    # Read distro info from /etc/os-release
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r") as f:
                distro_name = ""
                distro_version = ""
                for line in f:
                    line = line.strip()
                    if line.startswith("NAME="):
                        distro_name = line.split("=", 1)[1].strip('"')
                    elif line.startswith("VERSION="):
                        distro_version = line.split("=", 1)[1].strip('"')
                if distro_name:
                    ver_str = f" {distro_version}" if distro_version else ""
                    report(f"  Distribution: {distro_name}{ver_str}")
        except (PermissionError, FileNotFoundError, OSError):
            pass

    INTERESTING_PKGS = {
        "apache2", "httpd", "nginx", "mysql-server", "mariadb-server", "postgresql",
        "fail2ban", "ufw", "iptables", "selinux-utils", "apparmor", "firewalld",
        "openssh-server", "docker.io", "docker-ce", "openvpn", "wireguard", "wireguard-tools",
        "netcat", "netcat-traditional", "netcat-openbsd", "nmap", "tcpdump", "curl", "wget", "sudo",
        "gcc", "python3", "perl", "ruby"
    }

    # DEB packages
    dpkg_status = "/var/lib/dpkg/status"
    if os.path.exists(dpkg_status):
        report("  Package Manager: DEB (Debian/Ubuntu)")
        try:
            pkg_count = 0
            found_interesting = []
            pkg_name = ""
            pkg_version = ""
            with open(dpkg_status, "r") as f:
                for line in f:
                    if line.startswith("Package: "):
                        pkg_name = line[9:].strip()
                    elif line.startswith("Version: "):
                        pkg_version = line[9:].strip()
                    elif line == "\n" and pkg_name:
                        pkg_count += 1
                        if pkg_name in INTERESTING_PKGS:
                            found_interesting.append((pkg_name, pkg_version))
                        pkg_name = pkg_version = ""
                # Handle last block if file doesn't end with blank line
                if pkg_name:
                    pkg_count += 1
                    if pkg_name in INTERESTING_PKGS:
                        found_interesting.append((pkg_name, pkg_version))

            report(f"  Total DEB packages installed: {pkg_count}")
            report("  Packages of Interest found:")
            if found_interesting:
                for name, ver in sorted(found_interesting):
                    report(f"    {name} {ver}")
            else:
                report("    (none of the tracked packages found)")
        except (PermissionError, FileNotFoundError, OSError):
            report("  (could not read dpkg status)")

    # RPM packages
    elif os.path.exists("/var/lib/rpm"):
        report("  Package Manager: RPM (RedHat/CentOS/Fedora)")
        try:
            output = subprocess.check_output(
                ["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"],
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                timeout=30
            )
            lines = output.strip().split("\n")
            pkg_count = len(lines) if lines[0] else 0
            
            found_interesting = []
            for line in lines:
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    name, ver = parts
                    if name in INTERESTING_PKGS:
                        found_interesting.append((name, ver))
            
            report(f"  Total RPM packages installed: {pkg_count}")
            report("  Packages of Interest found:")
            if found_interesting:
                for name, ver in sorted(found_interesting):
                    report(f"    {name} {ver}")
            else:
                report("    (none of the tracked packages found)")
        except (OSError, subprocess.CalledProcessError):
            report("  (failed to query rpm database via rpm command)")

    else:
        report("  Package Manager: Unknown (no DEB or RPM detected)")

    # Additional package managers
    extra_managers = {
        "pacman": "/var/lib/pacman",
        "apk": "/etc/apk",
        "portage": "/var/db/pkg/gentoo",
    }
    for name, path in extra_managers.items():
        if os.path.exists(path):
            report(f"  Additional: {name} detected (at {path})")


def survey_security_products():
    section("Security Products")

    # Check for running AV/EDR processes via /proc/*/comm
    target_procs = {
        'clamd', 'freshclam', 'ossec', 'wazuh', 'selinux',
        'auditd', 'fail2ban', 'crowdsec', 'suricata', 'zeek',
    }
    found_procs = {}

    # Use cached process names from survey_processes() if available, else scan
    proc_data = _process_names if _process_names else {}
    if not proc_data:
        try:
            pids = [d for d in os.listdir('/proc') if d.isdigit()]
            for pid in pids:
                try:
                    with open(f"/proc/{pid}/comm", "r") as f:
                        proc_data[pid] = f.read().strip()
                except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
                    continue
        except (PermissionError, FileNotFoundError, OSError):
            pass

    for pid, comm in proc_data.items():
        if comm in target_procs:
            found_procs.setdefault(comm, []).append(pid)

    if found_procs:
        report("  Running security processes:")
        for proc_name, pids in sorted(found_procs.items()):
            report(f"    {proc_name}: PID(s) {', '.join(pids)}")
    else:
        report("  No known AV/EDR processes detected running")

    # SELinux check
    selinux_active = False
    # Check /proc/mounts for selinuxfs
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                if "selinuxfs" in line.split():
                    selinux_active = True
                    report("  SELinux: active (selinuxfs mounted)")
                    break
    except (PermissionError, FileNotFoundError, OSError):
        pass

    if not selinux_active and os.path.exists("/etc/selinux/config"):
        try:
            with open("/etc/selinux/config", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("SELINUX="):
                        mode = line.split("=", 1)[1] if "=" in line else "unknown"
                        report(f"  SELinux: installed (mode={mode})")
                        selinux_active = True
                        break
        except (PermissionError, FileNotFoundError, OSError):
            pass

    if not selinux_active:
        report("  SELinux: not detected")

    # AppArmor check
    if os.path.exists("/sys/kernel/security/apparmor"):
        report("  AppArmor: active")
    else:
        # Also check /proc/mounts for securityfs + apparmor
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    if "securityfs" in line.split():
                        # securityfs is mounted, check for apparmor subdir
                        # (we already checked the file above; if it doesn't exist, AppArmor not active)
                        break
        except (PermissionError, FileNotFoundError, OSError):
            pass
        report("  AppArmor: not active")


def survey_shell_history():
    section("Shell History (Last 50 Lines per User)")

    history_files = [".bash_history", ".zsh_history", ".python_history"]
    found_any = False

    for user in pwd.getpwall():
        # Only users with real login shells
        if user.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/bin/nologin"):
            continue
        if not user.pw_dir or not os.path.isdir(user.pw_dir):
            continue

        for hist_file in history_files:
            hist_path = os.path.join(user.pw_dir, hist_file)
            if os.path.exists(hist_path) and os.access(hist_path, os.R_OK):
                try:
                    with open(hist_path, "r", errors="replace") as f:
                        lines = f.readlines()
                    if lines:
                        found_any = True
                        last_entries = [l.rstrip() for l in lines[-50:] if l.strip()]
                        report(f"  {user.pw_name}: {hist_file} ({len(lines)} lines, showing last 50):")
                        for entry in last_entries:
                            report(f"    {entry}")
                except (PermissionError, FileNotFoundError, OSError):
                    pass

    if not found_any:
        report("  No readable shell history files found")

def survey_env_vars():
    section("Environment Variables")
    for k, v in os.environ.items():
        report(f"  {k}={safe_env_value(k, v)}")

def survey_container():
    section("Container & Virtualization Detection")
    if os.path.exists("/.dockerenv"):
        report("  [!] Running inside a Docker container (/.dockerenv found)")
    
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
            if "docker" in content: report("  [!] Cgroup indicates Docker")
            if "kubepods" in content: report("  [!] Cgroup indicates Kubernetes")
    except (PermissionError, FileNotFoundError, OSError): pass

def survey_kernel_modules():
    section("Loaded Kernel Modules")
    try:
        with open("/proc/modules", "r") as f:
            for line in f:
                report("  " + line.split()[0])
    except (PermissionError, FileNotFoundError, OSError): pass

def survey_ld_preload():
    section("LD_PRELOAD & Dynamic Linker")
    if "LD_PRELOAD" in os.environ:
        report(f"  [!] LD_PRELOAD env var is set: {os.environ['LD_PRELOAD']}")
    else:
        report("  LD_PRELOAD env var is NOT set.")
        
    if os.path.exists("/etc/ld.so.preload"):
        report("  [!] /etc/ld.so.preload exists. Contents:")
        _print_file_contents("/etc/ld.so.preload", prefix="    ")
    else:
        report("  /etc/ld.so.preload: not found")
        
    ld_conf_d = "/etc/ld.so.conf.d"
    if os.path.isdir(ld_conf_d):
        report(f"\n  {ld_conf_d}/:")
        try:
            for fname in sorted(os.listdir(ld_conf_d)):
                report(f"    File: {fname}")
        except (PermissionError, OSError):
            report("    (not readable)")

def survey_suid_sgid():
    section("SUID & SGID Binaries (Common Paths)")
    search_paths = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
    found = []
    
    for path in search_paths:
        if not os.path.isdir(path): continue
        try:
            for fname in os.listdir(path):
                full_path = os.path.join(path, fname)
                if os.path.isfile(full_path) and not os.path.islink(full_path):
                    try:
                        st = os.stat(full_path)
                        if st.st_mode & stat.S_ISUID or st.st_mode & stat.S_ISGID:
                            perms = oct(st.st_mode)[-4:]
                            found.append(f"  {perms}  {full_path}")
                    except (PermissionError, FileNotFoundError, OSError):
                        pass
        except (PermissionError, OSError):
            pass
            
    if found:
        for item in sorted(found):
            report(item)
    else:
        report("  No SUID/SGID binaries found in standard paths.")

def survey_sudoers():
    section("Sudoers Configuration")
    sudoers = "/etc/sudoers"
    if os.path.exists(sudoers):
        report(f"  {sudoers}:")
        _print_file_contents(sudoers, prefix="    ")
    else:
        report("  /etc/sudoers: not found")
        
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        report(f"\n  {sudoers_d}/:")
        try:
            for fname in sorted(os.listdir(sudoers_d)):
                full_path = os.path.join(sudoers_d, fname)
                if os.path.isfile(full_path) and not fname.endswith("~"):
                    report(f"    File: {fname}")
                    _print_file_contents(full_path, prefix="      ")
        except (PermissionError, OSError):
            report("    (not readable)")

def survey_mounts_shm():
    section("Mount Points & Memory Backed Storage")
    report("  Checking /proc/mounts (focusing on tmpfs, /tmp, /dev/shm):")
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    mpoint = parts[1]
                    if mpoint in ("/tmp", "/var/tmp", "/dev/shm") or "tmpfs" in parts[0] or "tmpfs" in parts[2]:
                        report(f"  {mpoint:15} {parts[2]:10} {parts[3]}")
    except (PermissionError, FileNotFoundError, OSError):
        report("  (could not read /proc/mounts)")

def survey_systemd_services():
    section("Systemd Services (/etc/systemd/system)")
    sysd_dir = "/etc/systemd/system"
    if os.path.isdir(sysd_dir):
        report(f"  {sysd_dir}/:")
        try:
            for fname in os.listdir(sysd_dir):
                if fname.endswith(".service"):
                    full_path = os.path.join(sysd_dir, fname)
                    if os.path.isfile(full_path):
                        report(f"\n    Service: {fname}")
                        _print_file_contents(full_path, prefix="      ")
        except (PermissionError, OSError):
            report("    (not readable)")

def survey_hosts_file():
    section("Hosts File (/etc/hosts)")
    if os.path.exists("/etc/hosts"):
        try:
            with open("/etc/hosts", "r", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        report(f"  {stripped}")
        except (PermissionError, FileNotFoundError, OSError):
            report("  (not readable)")
    else:
        report("  /etc/hosts: not found")

def survey_bash_profiles():
    section("Bash Profiles & Aliases")
    global_profiles = ["/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"]
    for gp in global_profiles:
        if os.path.exists(gp):
            report(f"  {gp}:")
            _print_file_contents(gp, prefix="    ")
            
    report("\n  User Profiles (~/.bashrc, ~/.bash_profile, ~/.profile):")
    try:
        for user in pwd.getpwall():
            if user.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/bin/nologin"):
                continue
            if not user.pw_dir or not os.path.isdir(user.pw_dir):
                continue
            
            for pfile in [".bashrc", ".bash_profile", ".profile"]:
                ppath = os.path.join(user.pw_dir, pfile)
                if os.path.exists(ppath):
                    report(f"    {user.pw_name}: {pfile}")
                    _print_file_contents(ppath, prefix="      ")
    except Exception as e:
        report(f"  (failed to parse user profiles: {e})")

def survey_recent_logins():
    section("Recent Logins (last)")
    try:
        output = subprocess.check_output(["last", "-n", "10"], stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
        for line in output.strip().split("\n"):
            if line.strip():
                report(f"  {line.strip()}")
    except (OSError, subprocess.CalledProcessError):
        report("  (failed to execute 'last' command)")

def survey_listening_ports():
    section("Listening Ports (TCP)")
    report(pad("Proto", 8) + pad("Local Address", 30) + pad("State", 15))
    report(pad("-----", 8) + pad("-------------", 30) + pad("-----", 15))
    
    tcp4 = _parse_proc_net("tcp", "/proc/net/tcp", is_v6=False)
    tcp6 = _parse_proc_net("tcp6", "/proc/net/tcp6", is_v6=True)
    
    found_any = False
    for proto, conns in [("TCP", tcp4), ("TCPv6", tcp6)]:
        for c in conns:
            if c[3] == "0A": # LISTEN
                report(pad(proto, 8) + pad(c[0], 30) + pad(c[2], 15))
                found_any = True
                
    if not found_any:
        report("  No listening TCP ports found.")

def survey_ssh_analysis():
    section("SSH Analysis")
    # Config check
    if os.path.exists("/etc/ssh/sshd_config"):
        try:
            report("  Checking /etc/ssh/sshd_config:")
            with open("/etc/ssh/sshd_config", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("PermitRootLogin") or line.startswith("PasswordAuthentication"):
                        report("    " + line)
        except (PermissionError, FileNotFoundError, OSError): pass
    
    # Authorized keys check
    report("\n  Checking for authorized_keys in /root and /home:")
    keys_paths = ["/root/.ssh/authorized_keys"]
    try:
        home_base = "/home"
        if os.path.exists(home_base):
            for user_dir in os.listdir(home_base):
                keys_paths.append(os.path.join(home_base, user_dir, ".ssh/authorized_keys"))
    except (PermissionError, FileNotFoundError, OSError): pass

    for ak_path in keys_paths:
        if os.path.exists(ak_path):
            report(f"    [!] Found authorized_keys at: {ak_path}")
            _print_file_contents(ak_path, prefix="      ")

def survey_arp():
    section("Network Neighbors (ARP Cache)")
    report(pad("IP Address", 20) + pad("HW Type", 10) + pad("Flags", 10) + "HW Address")
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
            for line in lines:
                p = line.split()
                if len(p) >= 4:
                    report(pad(p[0], 20) + pad(p[1], 10) + pad(p[2], 10) + p[3])
    except (PermissionError, FileNotFoundError, OSError): pass

def _tail_lines(filepath, n):
    """Read last N lines without loading the entire file into memory."""
    try:
        with open(filepath, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return []
            data = b""
            pos = size
            while pos > 0 and data.count(b"\n") <= n:
                read_size = min(8192, pos)
                pos -= read_size
                f.seek(pos)
                data = f.read(read_size) + data
        return data.decode("utf-8", errors="replace").splitlines()[-n:]
    except (PermissionError, FileNotFoundError, OSError):
        return []


def survey_recently_modified_files():
    section("Recently Modified Files (Last Hour)")
    report("  Scanning entire filesystem (excluding /proc, /sys, /dev, /run)...")

    SKIP_DIRS = frozenset(["/proc", "/sys", "/dev", "/run"])
    MAX_RESULTS = 100

    def _scan_with_find():
        """Use find command. Returns (lines, error_msg) tuple."""
        cmd = [
            "find", "/",
            "-path", "/proc", "-prune", "-o",
            "-path", "/sys", "-prune", "-o",
            "-path", "/dev", "-prune", "-o",
            "-path", "/run", "-prune", "-o",
            "-type", "f", "-mmin", "-60", "-print"
        ]
        # Use Popen instead of check_output: find returns exit code 1 on
        # permission-denied directories, which makes check_output throw
        # CalledProcessError and discard all partial results.
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        try:
            stdout, _ = proc.communicate(timeout=120)
            return stdout, None
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
            return stdout, "Scan timed out after 120 seconds (partial results shown)"

    def _scan_with_walk():
        """Pure Python fallback using os.walk."""
        cutoff = time.time() - 3600
        results = []
        for root, dirs, files in os.walk("/", topdown=True):
            # Prune pseudo-filesystems
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in SKIP_DIRS]
            for fname in files:
                if len(results) >= MAX_RESULTS:
                    return results, None
                fpath = os.path.join(root, fname)
                try:
                    if os.lstat(fpath).st_mtime >= cutoff:
                        results.append(fpath)
                except (PermissionError, FileNotFoundError, OSError):
                    pass
        return results, None

    output = None
    error_msg = None
    lines = []

    # Try find first, fall back to os.walk
    try:
        output, error_msg = _scan_with_find()
        if output:
            lines = [l.strip() for l in output.strip().split("\n") if l.strip()]
    except OSError:
        # find not available, use os.walk
        walk_results, error_msg = _scan_with_walk()
        lines = walk_results

    count = 0
    for line in lines:
        report(f"  {line}")
        count += 1
        if count >= MAX_RESULTS:
            report(f"  [!] Output capped at {MAX_RESULTS} files.")
            break

    if count == 0:
        report("  No recently modified files found.")
    if error_msg:
        report(f"  [!] {error_msg}")


def survey_anomaly_detection():
    section("Anomaly Detection (Threat Hunting)")
    findings = []
    
    # Suspicious execution locations
    SUSPICIOUS_DIRS = ["/tmp/", "/var/tmp/", "/dev/shm/", "/dev/mqueue/"]
    
    # Suspicious tool names
    SUSPICIOUS_TOOLS = {
        "nc", "ncat", "netcat", "socat", "nmap", "tcpdump",
        "wireshark", "tshark", "ettercap", "hydra", "john",
        "hashcat", "mimipenguin", "linpeas", "linenum",
        "pspy", "chisel", "ligolo"
    }
    
    pids = [d for d in os.listdir('/proc') if d.isdigit()]
    for pid in sorted(pids, key=int):
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/comm", "r", errors="replace") as f:
                name = f.read().strip()
            with open(f"/proc/{pid}/cmdline", "r", errors="replace") as f:
                cmdline = f.read().replace('\0', ' ').strip()
            
            ppid = ""
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        ppid = line.split(":")[1].strip()
                        break
            
            exe_lower = exe_path.lower()
            deleted = exe_path.endswith("(deleted)")
            
            # Check 1: Deleted executables (malware often deletes itself after execution)
            if deleted:
                findings.append(f"[!!!] DELETED BINARY: {name} (PID {pid}, PPID {ppid}) exe was: {exe_path}")
            
            # Check 2: Executables running from suspicious directories
            for sdir in SUSPICIOUS_DIRS:
                if exe_lower.startswith(sdir):
                    findings.append(f"[!!] SUSPICIOUS LOCATION: {name} (PID {pid}, PPID {ppid}) running from: {exe_path}")
                    break
            
            # Check 3: Known offensive/recon tools running
            if name.lower() in SUSPICIOUS_TOOLS:
                findings.append(f"[!] RECON/OFFENSIVE TOOL: {name} (PID {pid}, PPID {ppid}) cmdline: {cmdline[:120]}")
            
            # Check 4: Reverse shells — shell spawned with network redirection
            if name in ("bash", "sh", "dash", "zsh") and ("/dev/tcp/" in cmdline or "/dev/udp/" in cmdline):
                findings.append(f"[!!!] POSSIBLE REVERSE SHELL: {name} (PID {pid}, PPID {ppid}) cmdline: {cmdline[:120]}")
            
            # Check 5: Processes running from user home hidden directories
            if "/home/" in exe_path and "/." in exe_path:
                findings.append(f"[!!] HIDDEN DIR EXECUTION: {name} (PID {pid}, PPID {ppid}) running from: {exe_path}")
            
        except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
            continue
    
    # Output findings
    if findings:
        report(f"  *** {len(findings)} anomalies detected ***\n")
        for finding in findings:
            report(f"  {finding}")
    else:
        report("  No anomalies detected. All processes appear to be running from expected locations.")

def _read_log_source(filepath, depth, label=None):
    """Read a log file and report its contents. Returns True if lines were found."""
    if not os.path.exists(filepath):
        return False
    if not os.access(filepath, os.R_OK):
        report(f"  [!] Cannot read {filepath} — permission denied.")
        return False
    lines = _tail_lines(filepath, depth)
    if lines:
        display = label or filepath
        report(f"\n  --- {display} (last {depth} lines) ---")
        for line in lines:
            report(f"  {line.strip()}")
        return True
    return False


def survey_logs():
    section(f"Recent Logs (Last {config.log_depth} lines)")

    found_any = False

    # Primary system log: syslog (Debian/Ubuntu) or messages (RHEL/CentOS)
    for candidate in ["/var/log/syslog", "/var/log/messages"]:
        if _read_log_source(candidate, config.log_depth):
            found_any = True
            break

    # Fallback: journalctl for systemd distros without syslog files
    if not found_any:
        try:
            output = subprocess.check_output(
                ["journalctl", "--no-pager", "-n", str(config.log_depth)],
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                timeout=15
            )
            if output.strip():
                report(f"\n  --- journalctl (last {config.log_depth} entries) ---")
                for line in output.strip().split("\n"):
                    report(f"  {line.strip()}")
                found_any = True
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    # Security-critical logs — always check these independently
    # auth.log (Debian/Ubuntu) and secure (RHEL/CentOS) contain login/sudo/PAM events
    auth_depth = min(config.log_depth, 200)
    for auth_log in ["/var/log/auth.log", "/var/log/secure"]:
        if _read_log_source(auth_log, auth_depth):
            found_any = True
            break

    # Kernel log — hardware, driver, and kernel-level security events
    kern_depth = min(config.log_depth, 100)
    if _read_log_source("/var/log/kern.log", kern_depth):
        found_any = True
    else:
        # dmesg fallback for kernel ring buffer
        try:
            dmesg_lines = _tail_lines("/var/log/dmesg", 50)
            if not dmesg_lines:
                result = subprocess.check_output(
                    ["dmesg", "--time-format", "iso"],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                    timeout=10
                )
                if result.strip():
                    dmesg_lines = result.strip().split("\n")[-50:]
            if dmesg_lines:
                report(f"\n  --- dmesg (last 50 lines) ---")
                for line in dmesg_lines:
                    report(f"  {line.strip()}")
                found_any = True
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

    if not found_any:
        report("  No log sources available (no syslog, journalctl, or dmesg access).")

def main():
    parser = argparse.ArgumentParser(description='Linux System Survey — Living off the Land')
    parser.add_argument('-o', '--output', default='', help='Output file path (default: survey_<hostname>.txt)')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--skip', nargs='*', default=[], help='Module names to skip')
    parser.add_argument('--only', nargs='*', default=[], help='Only run these modules')
    parser.add_argument('--hash', action='store_true', help='Enable process hashing (MD5)')
    parser.add_argument('--log-depth', type=int, default=300, help='Number of log lines to include')
    args = parser.parse_args()

    if args.output:
        config.output_file = args.output
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config.output_file = os.path.join(script_dir, f"survey_{os.uname().nodename}.txt")
    config.output_format = args.format
    config.skip_modules = args.skip
    config.only_modules = args.only
    config.no_hash = not args.hash
    config.log_depth = args.log_depth

    if os.geteuid() != 0:
        print("WARNING: Script not running as root. The following modules will have limited data:")
        print("  - Processes (limited to current user)")
        print("  - Network (no program names in connections)")
        print("  - Logs (likely permission denied)")
        print("  - SSH config (may be restricted)")
    
    report("Starting Linux System Survey at " + time.ctime())

    ALL_MODULES = [
        ("system_info", survey_system_info),
        ("processes", survey_processes),
        ("network", survey_network),
        ("arp", survey_arp),
        ("listening_ports", survey_listening_ports),
        ("users", survey_users),
        ("recent_logins", survey_recent_logins),
        ("services", survey_services),
        ("systemd_services", survey_systemd_services),
        ("packages", survey_packages_detailed),
        ("firewall", survey_firewall),
        ("scheduled_tasks", survey_scheduled_tasks),
        ("security_products", survey_security_products),
        ("shell_history", survey_shell_history),
        ("bash_profiles", survey_bash_profiles),
        ("env_vars", survey_env_vars),
        ("container", survey_container),
        ("kernel_modules", survey_kernel_modules),
        ("ld_preload", survey_ld_preload),
        ("suid_sgid", survey_suid_sgid),
        ("sudoers", survey_sudoers),
        ("mounts", survey_mounts_shm),
        ("hosts_file", survey_hosts_file),
        ("ssh_analysis", survey_ssh_analysis),
        ("anomaly_detection", survey_anomaly_detection),
        ("logs", survey_logs),
        ("recently_modified_files", survey_recently_modified_files),

    ]

    # Filter modules based on --skip and --only
    if config.only_modules:
        modules = [(n, f) for n, f in ALL_MODULES if n in config.only_modules]
    else:
        modules = [(n, f) for n, f in ALL_MODULES if n not in config.skip_modules]

    # Validate output path BEFORE running modules
    _prohibited = ('/dev/', '/etc/', '/sys/', '/proc/', '/boot/')
    if any(os.path.abspath(config.output_file).startswith(p) for p in _prohibited):
        print(f"ERROR: Refusing to write to {config.output_file}")
        sys.exit(1)

    for name, func in modules:
        func()

    # Write output
    with open(config.output_file, "w") as f:
        f.writelines(OUTPUT_BUFFER)

    if config.output_format == 'json':
        json_file = config.output_file.rsplit('.', 1)[0] + '.json'
        with open(json_file, "w") as f:
            json.dump(json_sections, f, indent=2)
        print(f"JSON output saved to {json_file}")

    print(f"\nSurvey complete. Results saved to {config.output_file}")

if __name__ == "__main__":
    main()
