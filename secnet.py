#!/usr/bin/env python3
"""
Cyber Toolkit — All-in-One (Terminal Edition)
- Network scanner (interactive + CLI)
- SSH manager & SFTP upload (Paramiko; auto-installer with consent)
- Animated banner (typewriter + color fade, iSH-friendly)
- Searchable main menu + welcome summary
- History logging + export
- Graceful Ctrl+C everywhere

USAGE:
  Interactive: python3 cyber_toolkit_allinone.py
  CLI scan:    python3 cyber_toolkit_allinone.py netscan --range 192.168.1.0/24
  CLI ssh:     python3 cyber_toolkit_allinone.py ssh --hosts hosts.txt --cmd "hostname"
  CLI sftp:    python3 cyber_toolkit_allinone.py sftp-put --hosts hosts.txt -l local.txt -r /tmp/local.txt
"""

import argparse
import concurrent.futures
import datetime as _dt
import ipaddress
import json
import logging
import os
import queue
import socket
import sys
import threading
import time
from pathlib import Path

# -------------------- Optional paramiko import (auto-install) --------------------
HAS_PARAMIKO = True
try:
    import paramiko  # type: ignore
except Exception:
    HAS_PARAMIKO = False

def _auto_install_paramiko():
    """Ask to install paramiko; tries pip via current interpreter."""
    import subprocess
    print()
    print("Paramiko is required for SSH/SFTP features.")
    ans = input("Install Paramiko now with pip? [y/N]: ").strip().lower()
    if ans != "y":
        print("Skipping install. SSH features will be disabled.")
        return False
    try:
        print("Installing Paramiko… (this may take a moment)")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "paramiko"])
        global HAS_PARAMIKO
        import importlib
        importlib.invalidate_caches()
        paramiko_module = importlib.import_module("paramiko")
        globals()["paramiko"] = paramiko_module
        HAS_PARAMIKO = True
        print("Paramiko installed successfully.")
        return True
    except Exception as e:
        print(f"Paramiko installation failed: {e}")
        return False

# -------------------- Logging --------------------
LOGFILE = "cyber_toolkit.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOGFILE, encoding="utf-8"), logging.StreamHandler(sys.stdout)]
)

# -------------------- Colors & printing helpers --------------------
def _supports_color():
    if "--no-color" in sys.argv:
        return False
    return sys.stdout.isatty()

USE_COLOR = _supports_color()
if USE_COLOR:
    RED = "\033[31m"; GRN = "\033[32m"; YEL = "\033[33m"; BLU = "\033[34m"
    MAG = "\033[35m"; CYA = "\033[36m"; WHT = "\033[37m"; RST = "\033[0m"; BLD = "\033[1m"
else:
    RED = GRN = YEL = BLU = MAG = CYA = WHT = RST = BLD = ""

def info(msg): print(f"{BLU}[i]{RST} {msg}")
def ok(msg):   print(f"{GRN}[+]{RST} {msg}")
def warn(msg): print(f"{YEL}[!]{RST} {msg}")
def err(msg):  print(f"{RED}[-]{RST} {msg}")

# -------------------- State (welcome summary) --------------------
STATE_FILE = Path(".cyber_toolkit_state.json")
def _load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def _save_state(**kwargs):
    state = _load_state()
    state.update(kwargs)
    try:
        STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception:
        pass

# -------------------- Utilities --------------------
APP = "Cyber Toolkit — All-in-One"
DEFAULT_PORTS = [22, 80, 443, 8080, 8443, 3306, 53]
SOCKET_TIMEOUT = 0.8

HISTORY = []  # (timestamp, action, value)
HISTORY_LOCK = threading.Lock()

def now_ts():
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def add_history(action, value):
    with HISTORY_LOCK:
        HISTORY.append((now_ts(), action, str(value)))
        if len(HISTORY) > 2000:
            del HISTORY[:1000]

def export_history(path="cyber_history.txt"):
    with open(path, "w", encoding="utf-8") as f:
        for ts, action, value in HISTORY:
            f.write(f"[{ts}] {action}: {value}\n")
    ok(f"History exported to {path}")

# -------------------- Animated banner (typewriter + color fade) --------------------
def _adaptive_speed():
    # Slightly slower defaults on Linux/iSH (Alpine), a tad faster on desktop
    if sys.platform.startswith("linux"):
        return 0.0025
    elif sys.platform == "darwin":
        return 0.0018
    elif sys.platform == "win32":
        return 0.0018
    return 0.0020

def animated_banner():
    speed = _adaptive_speed()
    colors = [CYA, MAG, BLU, GRN, YEL, WHT] if USE_COLOR else [""]
    lines = [
        "============================================================",
        "   ____            _               _______     _ _    _ _    _ _    _",
        "  / ___| _   _ ___| |__   ___ _ __|__   __| __(_) | _(_) | _(_) | _| |_",
        "  \\___ \\| | | / __| '_ \\ / _ \\ '__|  | |   / _` | |/ / | |/ / | |/ / '_ \\",
        "   ___) | |_| \\__ \\ | | |  __/ |     | |  | (_| |   <| |   <| |   <| (_) |",
        "  |____/ \\__,_|___/_| |_|\\___|_|     |_|   \\__,_|_|\\_\\_|_|\\_\\_|_|\\_\\\\___/",
        "============================================================",
        f"🔐  Cyber Toolkit — Terminal Edition by Reax7",
        f"📅  {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"⚙️   Paramiko: {'Installed ✅' if HAS_PARAMIKO else 'Not installed ⚠️'}",
        "============================================================",
    ]
    try:
        for i, line in enumerate(lines):
            col = colors[i % len(colors)]
            for ch in line:
                sys.stdout.write(f"{col}{ch}{RST}")
                sys.stdout.flush()
                time.sleep(speed)
            sys.stdout.write("\n")
        time.sleep(0.25)
        print()
    except KeyboardInterrupt:
        # Graceful stop of animation
        print("\n")
        return

# -------------------- Network scanner --------------------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def hosts_from_cidr(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(h) for h in net.hosts()]
    except Exception:
        return []

def parse_range(range_str):
    r = range_str.strip()
    if "/" in r:
        return hosts_from_cidr(r)
    if "-" in r:
        try:
            a,b = r.split("-",1)
            a_ip = ipaddress.ip_address(a.strip()); b_ip = ipaddress.ip_address(b.strip())
            start = int(a_ip); end = int(b_ip)
            if end < start: start, end = end, start
            return [str(ipaddress.ip_address(i)) for i in range(start, end+1)]
        except Exception:
            return []
    try:
        ipaddress.ip_address(r); return [r]
    except Exception:
        return []

def tcp_connect(host, port, timeout=SOCKET_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, int(port)))
            return True
    except Exception:
        return False

def scan_host_ports(host, ports, timeout=SOCKET_TIMEOUT):
    return [p for p in ports if tcp_connect(host, p, timeout=timeout)]

def scan_hosts(hosts, ports, workers=200, timeout=SOCKET_TIMEOUT, progress=True):
    results = {}
    total = len(hosts)
    if total == 0:
        return results
    info(f"Scanning {total} hosts (ports: {ports})")
    start = time.time()

    def worker(h):
        try:
            return (h, scan_host_ports(h, ports, timeout=timeout))
        except Exception:
            return (h, [])

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, total or 1)) as ex:
        futures = {ex.submit(worker, h): h for h in hosts}
        checked = 0
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            try:
                h, openp = fut.result()
                if openp:
                    ok(f"{h} — open: {','.join(str(x) for x in openp)}")
                else:
                    info(f"{h} — closed/unreachable")
                results[h] = openp
                add_history("netscan_host", f"{h} -> {openp}")
            except Exception as e:
                err(f"{host} scan error: {e}")
                results[host] = []
            checked += 1
            if progress:
                print(f"{CYA}Progress: {checked}/{total}{RST}", end="\r")
    print()
    elapsed = time.time() - start
    info(f"Scan finished in {elapsed:.2f}s")
    return results

# -------------------- SSH manager (Paramiko) --------------------
def ensure_paramiko():
    global HAS_PARAMIKO
    if HAS_PARAMIKO:
        return True
    # offer auto-install
    if _auto_install_paramiko():
        return True
    warn("Paramiko not available. SSH features disabled.")
    return False

def _parse_target_line(s):
    s = s.strip()
    if "@" in s:
        user, rest = s.split("@",1)
    else:
        user, rest = None, s
    if ":" in rest:
        host, port = rest.split(":",1); port = int(port)
    else:
        host, port = rest, 22
    return user, host, port

def ssh_run_command(host_entry, cmd, pkey_path=None, timeout=10):
    if not ensure_paramiko():
        return (host_entry, False, "", "paramiko missing")
    import getpass
    user, host, port = _parse_target_line(host_entry)
    if user is None:
        try:
            user = getpass.getuser()
        except Exception:
            user = "root"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if pkey_path:
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(pkey_path)
                client.connect(hostname=host, port=port, username=user, pkey=pkey, timeout=timeout)
            except Exception:
                client.connect(hostname=host, port=port, username=user, key_filename=pkey_path, timeout=timeout)
        else:
            client.connect(hostname=host, port=port, username=user, timeout=timeout)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors='ignore')
        errt = stderr.read().decode(errors='ignore')
        client.close()
        add_history("ssh_cmd", f"{host_entry} :: {cmd}")
        return (host_entry, True, out.strip(), errt.strip())
    except Exception as e:
        logging.exception("SSH error")
        return (host_entry, False, "", str(e))

def ssh_sftp_put(host_entry, local_path, remote_path, pkey_path=None, timeout=10):
    if not ensure_paramiko():
        return (host_entry, False, "paramiko missing")
    import getpass
    user, host, port = _parse_target_line(host_entry)
    if user is None:
        try:
            user = getpass.getuser()
        except Exception:
            user = "root"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if pkey_path:
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(pkey_path)
                client.connect(hostname=host, port=port, username=user, pkey=pkey, timeout=timeout)
            except Exception:
                client.connect(hostname=host, port=port, username=user, key_filename=pkey_path, timeout=timeout)
        else:
            client.connect(hostname=host, port=port, username=user, timeout=timeout)
        sftp = client.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
        client.close()
        add_history("sftp_put", f"{host_entry} :: {local_path} -> {remote_path}")
        return (host_entry, True, "")
    except Exception as e:
        logging.exception("SFTP put error")
        return (host_entry, False, str(e))

# -------------------- Interactive menus --------------------
def netscan_interactive():
    info("Network Scanner — interactive")
    ip = get_local_ip()
    ok(f"Local IP detected: {ip}")
    default_cidr = None
    try:
        ipobj = ipaddress.ip_address(ip)
        if ipobj.version == 4:
            default_cidr = str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except Exception:
        default_cidr = None

    last_results = {}
    while True:
        print()
        print("1. Quick scan local subnet", f"({default_cidr})" if default_cidr else "")
        print("2. Custom range (CIDR / start-end / single IP)")
        print("3. Single IP")
        print("4. Set ports (current: {})".format(DEFAULT_PORTS))
        print("5. Save last results")
        print("0. Back")
        choice = input("Choose> ").strip()
        if choice == "1":
            if not default_cidr:
                warn("Auto subnet not available.")
                continue
            hosts = hosts_from_cidr(default_cidr)
            last_results = scan_hosts(hosts, DEFAULT_PORTS)
        elif choice == "2":
            rng = input("Enter range (CIDR or start-end): ").strip()
            hosts = parse_range(rng)
            if not hosts:
                warn("Could not parse range.")
                continue
            last_results = scan_hosts(hosts, DEFAULT_PORTS)
        elif choice == "3":
            ipt = input("IP: ").strip()
            last_results = scan_hosts([ipt], DEFAULT_PORTS)
        elif choice == "4":
            pstr = input("Enter comma-separated ports or leave empty to reset: ").strip()
            if not pstr:
                DEFAULT_PORTS[:] = [22,80,443,8080,8443,3306,53]; ok("Reset to default")
            else:
                try:
                    arr = [int(x.strip()) for x in pstr.split(",") if x.strip()]
                    DEFAULT_PORTS[:] = arr; ok(f"Ports set to {DEFAULT_PORTS}")
                except Exception:
                    warn("Invalid ports input")
        elif choice == "5":
            if last_results:
                path = f"netscan_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                with open(path, "w", encoding="utf-8") as f:
                    for h, ps in last_results.items():
                        f.write(f"{h}: {ps if ps else 'none'}\n")
                ok(f"Saved to {path}")
            else:
                warn("No results yet")
        elif choice == "0":
            break
        else:
            warn("Unknown option")

def ssh_interactive():
    if not ensure_paramiko():
        return
    info("SSH Manager — interactive")
    print("** WARNING: Only use on devices you own or have written permission to manage **")
    consent = input("Type I_HAVE_PERMISSION to continue: ").strip()
    if consent != "I_HAVE_PERMISSION":
        warn("Permission not confirmed. Aborting.")
        return

    hosts_file = input("Hosts file path (or leave empty to enter hosts manually): ").strip()
    hosts = []
    if hosts_file:
        try:
            hosts = [ln.strip() for ln in Path(hosts_file).read_text(encoding="utf-8").splitlines() if ln.strip()]
        except Exception as e:
            err(f"Could not open file: {e}")
            return
    else:
        print("Enter hosts (user@ip:port). Empty line to finish.")
        while True:
            h = input("host> ").strip()
            if not h:
                break
            hosts.append(h)

    if not hosts:
        warn("No hosts provided.")
        return

    print("Choose action:")
    print("1. Run command")
    print("2. Upload file (SFTP put)")
    print("0. Back")
    act = input("Action> ").strip()
    if act == "1":
        cmd = input("Command to run (quoted): ").strip()
        pkey = input("Private key path (leave empty to use default/agent): ").strip() or None
        concurrency = int(input("Concurrency (default 8): ").strip() or "8")
        info(f"Running command on {len(hosts)} hosts (concurrency {concurrency})")
        q = queue.Queue(); resq = queue.Queue()
        for h in hosts: q.put(h)
        def worker():
            while True:
                try:
                    h = q.get_nowait()
                except queue.Empty:
                    return
                res = ssh_run_command(h, cmd, pkey_path=pkey)
                resq.put(res)
                q.task_done()
        threads = []
        for _ in range(min(concurrency, len(hosts))):
            t = threading.Thread(target=worker, daemon=True); t.start(); threads.append(t)
        q.join()
        while not resq.empty():
            host, okflag, out, errtxt = resq.get()
            print("="*60)
            print(f"{host} -> {'OK' if okflag else 'ERROR'}")
            if out: print("--- STDOUT ---\n", out)
            if errtxt: print("--- STDERR / ERROR ---\n", errtxt)
    elif act == "2":
        local = input("Local file path: ").strip()
        remote = input("Remote destination path: ").strip()
        pkey = input("Private key path (optional): ").strip() or None
        concurrency = int(input("Concurrency (default 6): ").strip() or "6")
        q = queue.Queue(); resq = queue.Queue()
        for h in hosts: q.put(h)
        def worker_put():
            while True:
                try:
                    h = q.get_nowait()
                except queue.Empty:
                    return
                res = ssh_sftp_put(h, local, remote, pkey_path=pkey)
                resq.put(res)
                q.task_done()
        threads=[]
        for _ in range(min(concurrency,len(hosts))):
            t = threading.Thread(target=worker_put, daemon=True); t.start(); threads.append(t)
        q.join()
        while not resq.empty():
            h, okf, msg = resq.get()
            print(f"{h} -> {'OK' if okf else 'ERROR'} {msg}")
    else:
        info("Back")

# -------------------- Main interactive launcher (with search) --------------------
def main_menu():
    # Welcome & last run
    state = _load_state()
    last_used = state.get("last_used")
    animated_banner()
    if last_used:
        print(f"{CYA}Welcome back! Last used on: {last_used}{RST}")
    print(f"{CYA}Modules: NetScan ✅ | SSH {'✅' if HAS_PARAMIKO else '⚠️ (install to enable)'} | SFTP {'✅' if HAS_PARAMIKO else '⚠️'}{RST}")
    print()

    options = {
        "1": "scan",
        "2": "ssh",
        "3": "history",
        "0": "exit",
        # aliases for search
        "scan": "scan",
        "netscan": "scan",
        "ssh": "ssh",
        "sftp": "ssh",
        "history": "history",
        "export": "history",
        "exit": "exit",
        "quit": "exit",
        "q": "exit",
    }

    while True:
        print("Type a number or search (e.g., 'scan', 'ssh', 'history', 'exit'):")
        print("  1) Network Scanner")
        print("  2) SSH Manager / SFTP (authorized use)")
        print("  3) Export history")
        print("  0) Exit")
        choice = input("> ").strip().lower()
        action = options.get(choice, None)
        if action == "scan":
            netscan_interactive()
        elif action == "ssh":
            ssh_interactive()
        elif action == "history":
            path = input("Save history to (default cyber_history.txt): ").strip() or "cyber_history.txt"
            export_history(path)
        elif action == "exit":
            info("Exiting.")
            _save_state(last_used=now_ts())
            break
        else:
            warn("Not a valid option. Try: 1, 2, 3, 0 or 'scan', 'ssh', 'history', 'exit'.")

# -------------------- CLI --------------------
def build_parser():
    p = argparse.ArgumentParser(description="Cyber Toolkit — scanner + SSH manager (authorized use only)")
    sub = p.add_subparsers(dest="mode")

    ns = sub.add_parser("netscan", help="Network scan (CIDR / range / single IP)")
    ns.add_argument("--range", "-r", help="CIDR or range (192.168.1.0/24 or 192.168.1.1-192.168.1.10)")
    ns.add_argument("--ip", "-i", help="Single IP to scan")
    ns.add_argument("--ports", "-p", nargs="+", type=int, help=f"Ports to check (default {DEFAULT_PORTS})", default=DEFAULT_PORTS)
    ns.add_argument("--workers", "-w", type=int, default=200)
    ns.add_argument("--timeout", "-t", type=float, default=SOCKET_TIMEOUT)
    ns.add_argument("--save", "-s", help="Save results to file")

    ss = sub.add_parser("ssh", help="Run SSH command on hosts (requires paramiko)")
    ss.add_argument("--hosts", "-H", help="Hosts file (one per line: user@host:port or host:port)")
    ss.add_argument("--cmd", "-c", help="Command to run (quoted)")
    ss.add_argument("--key", "-k", help="Private key path (optional)")
    ss.add_argument("--concurrency", "-n", type=int, default=8)

    sf = sub.add_parser("sftp-put", help="Upload a file to hosts via SFTP (requires paramiko)")
    sf.add_argument("--hosts", "-H", help="Hosts file")
    sf.add_argument("--local", "-l", help="Local file path", required=True)
    sf.add_argument("--remote", "-r", help="Remote path (destination)", required=True)
    sf.add_argument("--key", "-k", help="Private key path (optional)")
    sf.add_argument("--concurrency", "-n", type=int, default=6)

    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return p

def cli_netscan(args):
    if args.ip:
        hosts = [args.ip]
    elif args.range:
        hosts = parse_range(args.range)
    else:
        ip = get_local_ip()
        try:
            ipobj = ipaddress.ip_address(ip)
            if ipobj.version == 4:
                hosts = hosts_from_cidr(f"{ip}/24")
            else:
                print("Could not auto-detect range; specify --range")
                return
        except Exception:
            print("Could not auto-detect range; specify --range")
            return
    res = scan_hosts(hosts, args.ports, workers=args.workers, timeout=args.timeout, progress=True)
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            for h,p in res.items():
                f.write(f"{h}: {','.join(str(x) for x in p) if p else 'none'}\n")
        ok(f"Saved to {args.save}")

def cli_ssh(args):
    if not ensure_paramiko():
        return
    if not args.hosts or not args.cmd:
        err("Provide both --hosts and --cmd")
        return
    consent = input("Type I_HAVE_PERMISSION to confirm authorized access: ").strip()
    if consent != "I_HAVE_PERMISSION":
        warn("Permission not confirmed. Aborting.")
        return
    try:
        hosts = [ln.strip() for ln in Path(args.hosts).read_text(encoding="utf-8").splitlines() if ln.strip()]
    except Exception as e:
        err(f"Could not open hosts file: {e}"); return
    q = queue.Queue(); resq = queue.Queue()
    for h in hosts: q.put(h)
    def worker():
        while True:
            try:
                h = q.get_nowait()
            except queue.Empty:
                return
            r = ssh_run_command(h, args.cmd, pkey_path=args.key)
            resq.put(r)
            q.task_done()
    threads=[]
    for _ in range(min(args.concurrency, len(hosts))):
        t = threading.Thread(target=worker, daemon=True); t.start(); threads.append(t)
    q.join()
    while not resq.empty():
        host, okflag, out, errt = resq.get()
        print("="*50)
        print(host, "OK" if okflag else "ERROR")
        if out: print("--- OUT ---\n", out)
        if errt: print("--- ERR ---\n", errt)

def cli_sftp_put(args):
    if not ensure_paramiko():
        return
    try:
        hosts = [ln.strip() for ln in Path(args.hosts).read_text(encoding="utf-8").splitlines() if ln.strip()]
    except Exception as e:
        err(f"Could not open hosts file: {e}"); return
    consent = input("Type I_HAVE_PERMISSION to confirm authorized access: ").strip()
    if consent != "I_HAVE_PERMISSION":
        warn("Permission not confirmed. Aborting.")
        return
    q = queue.Queue(); resq = queue.Queue()
    for h in hosts: q.put(h)
    def worker():
        while True:
            try:
                h = q.get_nowait()
            except queue.Empty:
                return
            r = ssh_sftp_put(h, args.local, args.remote, pkey_path=args.key)
            resq.put(r)
            q.task_done()
    threads=[]
    for _ in range(min(args.concurrency, len(hosts))):
        t = threading.Thread(target=worker, daemon=True); t.start(); threads.append(t)
    q.join()
    while not resq.empty():
        h, okf, msg = resq.get()
        print(h, "OK" if okf else f"ERROR: {msg}")

# -------------------- Main --------------------
def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.no_color:
        global USE_COLOR, RED, GRN, YEL, BLU, MAG, CYA, WHT, RST, BLD
        USE_COLOR = False
        RED = GRN = YEL = BLU = MAG = CYA = WHT = RST = BLD = ""
    if args.mode is None:
        try:
            main_menu()
        except KeyboardInterrupt:
            print()
            warn("Interrupted; exiting.")
            _save_state(last_used=now_ts())
        return
    if args.mode == "netscan":
        try:
            cli_netscan(args)
        except KeyboardInterrupt:
            print(); warn("Scan interrupted.")
    elif args.mode == "ssh":
        try:
            cli_ssh(args)
        except KeyboardInterrupt:
            print(); warn("SSH run interrupted.")
    elif args.mode == "sftp-put":
        try:
            cli_sftp_put(args)
        except KeyboardInterrupt:
            print(); warn("SFTP upload interrupted.")
    else:
        parser.print_help()
    _save_state(last_used=now_ts())

if __name__ == "__main__":
    main()
