#!/usr/bin/env python3
"""
Simple Network Scanner for terminals (iSH-friendly)
- Interactive menu + CLI mode
- Uses TCP connect to detect live hosts and open ports
- No external dependencies (stdlib only)
- Works on iSH (Alpine), Linux, macOS, Windows (python3)
"""

import argparse
import concurrent.futures
import ipaddress
import socket
import sys
import time
from datetime import datetime

APP = "iSH NetScan"
DEFAULT_PORTS = [22, 80, 443, 8080, 8443, 3306, 53]  # common ports (customizable)
SOCKET_TIMEOUT = 0.8  # seconds per connect attempt (tune for iSH/network)

# ----------------- Colors -----------------
def supports_color():
    if "--no-color" in sys.argv:
        return False
    if sys.platform == "win32":
        return sys.stdout.isatty()
    return sys.stdout.isatty()

USE_COLOR = supports_color()
if USE_COLOR:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; C = "\033[36m"; W = "\033[37m"; BR = "\033[0m"
else:
    R = G = Y = B = M = C = W = BR = ""

def banner():
    print(f"{C}{'='*60}{BR}")
    print(f"{C}🔎 {APP}  —  simple TCP host & port scanner{BR}")
    print(f"{C}{'='*60}{BR}")

def info(msg): print(f"{B}[i]{BR} {msg}")
def ok(msg):   print(f"{G}[+]{BR} {msg}")
def warn(msg): print(f"{Y}[!]{BR} {msg}")
def err(msg):  print(f"{R}[-]{BR} {msg}")

# ----------------- Utilities -----------------
def now_str(): return datetime.now().strftime("%Y-%m-%d_%H%M%S")

def get_local_ip():
    """Best-effort local IP by opening a UDP socket to a public address (no packet sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        # doesn't actually send packets; used to pick an outbound interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # fallback: hostname resolution
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def hosts_from_cidr(cidr):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        # exclude network and broadcast for IPv4 so we only return usable hosts
        return [str(h) for h in net.hosts()]
    except Exception:
        return []

def parse_range(range_str):
    """Accepts:
       - CIDR: 192.168.1.0/24
       - IP-IP: 192.168.1.1-192.168.1.30
       - single IP: 192.168.1.5
    """
    range_str = range_str.strip()
    if "/" in range_str:
        return hosts_from_cidr(range_str)
    if "-" in range_str:
        try:
            a, b = range_str.split("-", 1)
            a_ip = ipaddress.ip_address(a.strip())
            b_ip = ipaddress.ip_address(b.strip())
            if a_ip.version != b_ip.version:
                return []
            start = int(a_ip)
            end = int(b_ip)
            if end < start:
                start, end = end, start
            return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
        except Exception:
            return []
    # single ip
    try:
        ipaddress.ip_address(range_str)
        return [range_str]
    except Exception:
        return []

# ----------------- Network checks -----------------
def tcp_connect(host, port, timeout=SOCKET_TIMEOUT):
    """Return True if TCP connect succeeded to host:port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        s.close()
        return True
    except Exception:
        return False

def scan_host_ports(host, ports, timeout=SOCKET_TIMEOUT):
    open_ports = []
    for p in ports:
        if tcp_connect(host, p, timeout=timeout):
            open_ports.append(p)
    return open_ports

# ----------------- Runner / Threaded scanning -----------------
def scan_hosts(hosts, ports, workers=200, timeout=SOCKET_TIMEOUT, progress=True):
    results = {}
    total = len(hosts)
    if total == 0:
        return results
    info(f"Scanning {total} hosts, common ports: {ports}")
    start = time.time()
    # For each host, run port scan in thread pool
    def worker(h):
        try:
            openp = scan_host_ports(h, ports, timeout=timeout)
            return (h, openp)
        except Exception:
            return (h, [])
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, total or 1)) as ex:
        future_to_host = {ex.submit(worker, h): h for h in hosts}
        checked = 0
        for fut in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[fut]
            try:
                h, openp = fut.result()
                if openp:
                    ok(f"{h} — open: {','.join(str(x) for x in openp)}")
                else:
                    info(f"{h} — closed/unreachable")
                results[h] = openp
            except Exception as e:
                err(f"{host} scan error: {e}")
                results[host] = []
            checked += 1
            if progress:
                print(f"{C}Progress: {checked}/{total}{BR}", end="\r")
    print()  # newline after progress
    elapsed = time.time() - start
    info(f"Finished scanning in {elapsed:.2f}s")
    return results

# ----------------- Logging -----------------
def save_results(results, path=None):
    if path is None:
        path = f"netscan_{now_str()}.log"
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"{APP} results - {datetime.now().isoformat()}\n")
        for host, ports in results.items():
            f.write(f"{host}: {','.join(str(x) for x in ports) if ports else 'none'}\n")
    ok(f"Saved results to {path}")
    return path

# ----------------- Interactive menu -----------------
def interactive_menu():
    banner()
    local_ip = get_local_ip()
    info(f"Detected local IP: {local_ip}")
    default_cidr = None
    try:
        # try to build /24 by default for IPv4
        ip_obj = ipaddress.ip_address(local_ip)
        if ip_obj.version == 4:
            net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            default_cidr = str(net)
    except Exception:
        default_cidr = None

    while True:
        print()
        print(f"{C}1.{BR} Quick scan local subnet ({default_cidr or 'none'})")
        print(f"{C}2.{BR} Custom range (CIDR or start-end or single IP)")
        print(f"{C}3.{BR} Scan single IP")
        print(f"{C}4.{BR} Set ports (current: {DEFAULT_PORTS})")
        print(f"{C}5.{BR} Save last results to file")
        print(f"{C}6.{BR} Toggle verbose progress (default on)")
        print(f"{C}0.{BR} Exit")
        choice = input(f"{C}Select> {BR}").strip()
        if choice == "1":
            if not default_cidr:
                warn("Local subnet not detected. Use option 2 to specify range.")
                continue
            hosts = hosts_from_cidr(default_cidr)
            res = scan_hosts(hosts, DEFAULT_PORTS)
            global LAST_RESULTS
            LAST_RESULTS = res
        elif choice == "2":
            r = input("Enter CIDR (e.g. 192.168.1.0/24) or range (192.168.1.1-192.168.1.30): ").strip()
            hosts = parse_range(r)
            if not hosts:
                warn("Could not parse the range.")
                continue
            res = scan_hosts(hosts, DEFAULT_PORTS)
            LAST_RESULTS = res
        elif choice == "3":
            ip = input("IP address: ").strip()
            if not ip:
                continue
            res = scan_hosts([ip], DEFAULT_PORTS)
            LAST_RESULTS = res
        elif choice == "4":
            pstr = input("Enter comma-separated ports (e.g. 22,80,443) or leave empty to reset default: ").strip()
            if not pstr:
                warn("Resetting to default ports.")
                DEFAULT_PORTS[:] = [22, 80, 443, 8080, 8443, 3306, 53]
            else:
                try:
                    arr = [int(x.strip()) for x in pstr.split(",") if x.strip()]
                    DEFAULT_PORTS[:] = arr
                    ok(f"Ports set to: {DEFAULT_PORTS}")
                except Exception:
                    warn("Invalid ports input.")
        elif choice == "5":
            if 'LAST_RESULTS' in globals() and LAST_RESULTS:
                path = save_results(LAST_RESULTS)
            else:
                warn("No results to save. Scan first.")
        elif choice == "6":
            # toggle progress by adjusting a module-level variable; easiest is to flip a global
            global SHOW_PROGRESS
            SHOW_PROGRESS = not globals().get("SHOW_PROGRESS", True)
            ok(f"Verbose progress now {'on' if SHOW_PROGRESS else 'off'}")
        elif choice == "0":
            info("Exiting.")
            break
        else:
            warn("Unknown option. Choose again.")

# ----------------- CLI mode -----------------
def cli_mode(args):
    # Build host list
    hosts = []
    if args.range:
        hosts = parse_range(args.range)
        if not hosts:
            err("Could not parse range. Exiting.")
            return
    elif args.ip:
        hosts = [args.ip]
    else:
        # if no hosts provided, try default /24
        local = get_local_ip()
        try:
            ip_obj = ipaddress.ip_address(local)
            if ip_obj.version == 4:
                hosts = hosts_from_cidr(f"{local}/24")
                info(f"Auto-chosen range: {local}/24")
        except Exception:
            err("No hosts or range provided and auto-detect failed.")
            return

    ports = args.ports if args.ports else DEFAULT_PORTS
    # run scan
    results = scan_hosts(hosts, ports, workers=args.workers, timeout=args.timeout, progress=not args.quiet)
    if args.save:
        save_results(results, args.save)

# ----------------- Argument parser -----------------
def build_parser():
    p = argparse.ArgumentParser(description=f"{APP} — simple terminal network scanner")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    sub = p.add_mutually_exclusive_group()
    sub.add_argument("--range", "-r", help="Target range (CIDR, start-end, or single IP). Example: 192.168.1.0/24")
    sub.add_argument("--ip", "-i", help="Single IP to scan")
    p.add_argument("--ports", "-p", nargs="+", type=int, help=f"Ports to scan (default {DEFAULT_PORTS})")
    p.add_argument("--workers", "-w", type=int, default=200, help="Thread pool size")
    p.add_argument("--timeout", "-t", type=float, default=SOCKET_TIMEOUT, help="TCP connect timeout (s)")
    p.add_argument("--save", "-s", help="Save results to file path")
    p.add_argument("--quiet", action="store_true", help="Suppress progress output")
    p.add_argument("--interactive", action="store_true", help="Start interactive menu")
    return p

# ----------------- Main -----------------
def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.no_color:
        # disable colors for this run
        global USE_COLOR, R, G, Y, B, M, C, W, BR
        USE_COLOR = False
        R = G = Y = B = M = C = W = BR = ""
    if args.interactive:
        interactive_menu()
    elif not any([args.range, args.ip, args.interactive]):
        # No arguments -> run interactive by default
        interactive_menu()
    else:
        # CLI mode
        if args.ports:
            args.ports = args.ports
        cli_mode(args)

if __name__ == "__main__":
    # globals for toggles
    SHOW_PROGRESS = True
    LAST_RESULTS = {}
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user. Exiting.")
        sys.exit(0)
