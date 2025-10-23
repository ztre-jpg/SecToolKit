#!/usr/bin/env python3
# Security Toolkit - CLI (no GUI, no external deps)
# Works in iPhone ISH / Linux / macOS / Windows terminals
# Features: Password/Token/PIN/Username/Email generators, Strength check, MD5/SHA256, Base64, Diceware, UUID, Color HEX

import argparse, base64, hashlib, math, os, random, re, string, sys, uuid, textwrap
from datetime import datetime

APP_NAME = "Security Toolkit (CLI)"

# ---------------- Colors / Styling ----------------
def _supports_color():
    if "--no-color" in sys.argv:
        return False
    if sys.platform == "win32":
        return sys.stdout.isatty()
    return sys.stdout.isatty()

USE_COLOR = _supports_color()

class C:
    R = "\033[31m" if USE_COLOR else ""
    G = "\033[32m" if USE_COLOR else ""
    Y = "\033[33m" if USE_COLOR else ""
    B = "\033[34m" if USE_COLOR else ""
    M = "\033[35m" if USE_COLOR else ""
    C = "\033[36m" if USE_COLOR else ""
    W = "\033[37m" if USE_COLOR else ""
    BOLD = "\033[1m" if USE_COLOR else ""
    DIM = "\033[2m" if USE_COLOR else ""
    RS = "\033[0m" if USE_COLOR else ""

def banner():
    bar = f"{C.M}{'─'*58}{C.RS}"
    print(f"{bar}\n{C.BOLD}{C.C}🔐 {APP_NAME}{C.RS}\n{bar}")

def line():
    print(f"{C.DIM}{'-'*58}{C.RS}")

# ---------------- Generators & Helpers ----------------
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/\\|"

def gen_password(length=12, upper=True, lower=True, digits=True, symbols=True):
    pools = []
    if upper:  pools.append(string.ascii_uppercase)
    if lower:  pools.append(string.ascii_lowercase)
    if digits: pools.append(string.digits)
    if symbols:pools.append(SYMBOLS)
    if not pools: return ""
    allchars = "".join(pools)
    length = max(4, int(length))
    # ensure at least one from each selected pool
    pwd = [random.choice(pool) for pool in pools]
    while len(pwd) < length:
        pwd.append(random.choice(allchars))
    random.shuffle(pwd)
    return "".join(pwd[:length])

def password_strength(pw: str):
    score = 0
    if len(pw) >= 8: score += 1
    if re.search(r"[A-Z]", pw): score += 1
    if re.search(r"[a-z]", pw): score += 1
    if re.search(r"\d", pw): score += 1
    if re.search(r"[^A-Za-z0-9]", pw): score += 1
    labels = ["Very Weak","Weak","Moderate","Strong","Very Strong","Excellent"]
    label = labels[min(score, 5)]
    charset = 0
    if re.search(r"[A-Z]", pw): charset += 26
    if re.search(r"[a-z]", pw): charset += 26
    if re.search(r"\d", pw): charset += 10
    if re.search(r"[^A-Za-z0-9]", pw): charset += 32
    entropy = round(len(pw) * math.log2(charset), 2) if charset else 0.0
    return label, entropy, score

def rand_token(n=32): return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(max(8,int(n))))
def rand_pin(n=6):    return "".join(random.choice(string.digits) for _ in range(max(1,int(n))))
def rand_username(n=8): return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(max(3,int(n))))
def rand_email(name=""):
    domains = ["example.com","mail.com","test.org","domain.net"]
    local = name.strip().lower() if name.strip() else rand_username(8)
    return f"{local}@{random.choice(domains)}"
def md5_hash(s): return hashlib.md5(s.encode()).hexdigest()
def sha256_hash(s): return hashlib.sha256(s.encode()).hexdigest()
def b64_encode(s): return base64.b64encode(s.encode()).decode()
def b64_decode(s):
    try: return base64.b64decode(s.encode()).decode()
    except Exception: return None
def diceware(n=6):
    words = ["apple","basic","crane","delta","ember","folio","grape","harbor","ionic","jungle",
             "kettle","lemon","mango","nebula","onyx","panda","quartz","raven","sigma","tango",
             "ultra","vivid","willow","xenon","yonder","zephyr"]
    n = max(3, min(12, int(n)))
    return " ".join(random.choice(words) for _ in range(n))
def color_hex(): return "#{:06X}".format(random.randint(0, 0xFFFFFF))
def new_uuid(): return str(uuid.uuid4())

# ---------------- History (in-memory + optional save) ----------------
HISTORY = []  # tuples: (timestamp, action, value)

def add_history(action, value):
    HISTORY.append((datetime.now().strftime("%H:%M:%S"), action, str(value)))
    # cap to reasonable size
    if len(HISTORY) > 500:
        del HISTORY[: len(HISTORY) - 500]

def print_history():
    if not HISTORY:
        print(f"{C.Y}No history yet.{C.RS}")
        return
    for i, (ts, action, value) in enumerate(HISTORY, 1):
        print(f"{C.DIM}{i:03d}{C.RS} [{ts}] {C.B}{action}{C.RS}: {value}")

def export_history(path="security_toolkit_history.txt"):
    with open(path, "w", encoding="utf-8") as f:
        for ts, action, value in HISTORY:
            f.write(f"[{ts}] {action}: {value}\n")
    print(f"{C.G}Saved history to {path}{C.RS}")

# ---------------- Menu UI ----------------
MENU_TEXT = f"""
{C.BOLD}{C.C}Select an option by number:{C.RS}
  {C.B}1{C.RS}. Password generator
  {C.B}2{C.RS}. Password strength check
  {C.B}3{C.RS}. Token generator
  {C.B}4{C.RS}. PIN generator
  {C.B}5{C.RS}. Username generator
  {C.B}6{C.RS}. Email generator
  {C.B}7{C.RS}. MD5 hash
  {C.B}8{C.RS}. SHA256 hash
  {C.B}9{C.RS}. Base64 encode
 {C.B}10{C.RS}. Base64 decode
 {C.B}11{C.RS}. Diceware passphrase
 {C.B}12{C.RS}. UUID generate
 {C.B}13{C.RS}. Color HEX generate
 {C.B}14{C.RS}. Show history
 {C.B}15{C.RS}. Export history
 {C.B}0{C.RS}. Exit
"""

def menu_loop():
    while True:
        banner()
        print(MENU_TEXT)
        choice = input(f"{C.BOLD}{C.Y}#>{C.RS} ").strip()
        line()
        if choice == "1":
            try:
                ln = int(input("Length (default 16): ") or "16")
                use_u = (input("Uppercase? [Y/n]: ") or "y").lower().startswith("y")
                use_l = (input("Lowercase? [Y/n]: ") or "y").lower().startswith("y")
                use_d = (input("Digits?    [Y/n]: ") or "y").lower().startswith("y")
                use_s = (input("Symbols?   [Y/n]: ") or "y").lower().startswith("y")
            except Exception:
                print(f"{C.R}Invalid input, using defaults.{C.RS}")
                ln, use_u, use_l, use_d, use_s = 16, True, True, True, True
            pw = gen_password(ln, use_u, use_l, use_d, use_s)
            label, entropy, score = password_strength(pw)
            print(f"{C.G}Password:{C.RS} {pw}")
            print(f"{C.B}Strength:{C.RS} {label}  |  Entropy: {entropy} bits")
            add_history("Password", pw)

        elif choice == "2":
            pw = input("Password to check: ")
            label, entropy, score = password_strength(pw)
            print(f"{C.B}Strength:{C.RS} {label}  |  Entropy: {entropy} bits")
            add_history("Strength", f"{label} ({entropy} bits)")

        elif choice == "3":
            ln = int(input("Token length (default 32): ") or "32")
            t = rand_token(ln)
            print(f"{C.G}Token:{C.RS} {t}")
            add_history("Token", t)

        elif choice == "4":
            ln = int(input("PIN length (default 6): ") or "6")
            p = rand_pin(ln)
            print(f"{C.G}PIN:{C.RS} {p}")
            add_history("PIN", p)

        elif choice == "5":
            ln = int(input("Username length (default 8): ") or "8")
            u = rand_username(ln)
            print(f"{C.G}Username:{C.RS} {u}")
            add_history("Username", u)

        elif choice == "6":
            base = input("Local-part (optional): ")
            em = rand_email(base)
            print(f"{C.G}Email:{C.RS} {em}")
            add_history("Email", em)

        elif choice == "7":
            s = input("Text to MD5: ")
            h = md5_hash(s)
            print(f"{C.G}MD5:{C.RS} {h}")
            add_history("MD5", h)

        elif choice == "8":
            s = input("Text to SHA256: ")
            h = sha256_hash(s)
            print(f"{C.G}SHA256:{C.RS} {h}")
            add_history("SHA256", h)

        elif choice == "9":
            s = input("Text to Base64 encode: ")
            out = b64_encode(s)
            print(f"{C.G}Base64 (enc):{C.RS} {out}")
            add_history("Base64 enc", out)

        elif choice == "10":
            s = input("Text to Base64 decode: ")
            out = b64_decode(s)
            if out is None:
                print(f"{C.R}Invalid Base64.{C.RS}")
            else:
                print(f"{C.G}Base64 (dec):{C.RS} {out}")
                add_history("Base64 dec", out)

        elif choice == "11":
            n = int(input("Words (default 6): ") or "6")
            phrase = diceware(n)
            print(f"{C.G}Passphrase:{C.RS} {phrase}")
            add_history("Diceware", phrase)

        elif choice == "12":
            u = new_uuid()
            print(f"{C.G}UUID:{C.RS} {u}")
            add_history("UUID", u)

        elif choice == "13":
            col = color_hex()
            print(f"{C.G}HEX:{C.RS} {col}")
            add_history("Color HEX", col)

        elif choice == "14":
            print_history()

        elif choice == "15":
            path = input("Save to file (default security_toolkit_history.txt): ").strip() or "security_toolkit_history.txt"
            export_history(path)

        elif choice == "0":
            print(f"{C.C}Bye!{C.RS}")
            break

        else:
            print(f"{C.R}Unknown option.{C.RS}")

        line()
        input(f"{C.DIM}Press Enter to continue…{C.RS}")
        os.system("clear" if os.name != "nt" else "cls")

# ---------------- Argparse (direct commands) ----------------
def build_parser():
    p = argparse.ArgumentParser(
        description=f"{APP_NAME} — run with no args for interactive menu.",
        formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    # password
    sp = sub.add_parser("password", help="Generate a password")
    sp.add_argument("--length", "-l", type=int, default=16)
    sp.add_argument("--no-upper", action="store_true")
    sp.add_argument("--no-lower", action="store_true")
    sp.add_argument("--no-digits", action="store_true")
    sp.add_argument("--no-symbols", action="store_true")

    # strength
    ss = sub.add_parser("strength", help="Check password strength")
    ss.add_argument("password")

    # token / pin / username / email
    st = sub.add_parser("token", help="Generate random token")
    st.add_argument("--length", "-l", type=int, default=32)

    spi = sub.add_parser("pin", help="Generate numeric PIN")
    spi.add_argument("--length", "-l", type=int, default=6)

    su = sub.add_parser("username", help="Generate username")
    su.add_argument("--length", "-l", type=int, default=8)

    se = sub.add_parser("email", help="Generate email")
    se.add_argument("--name", "-n", default="")

    # hashes
    sm = sub.add_parser("md5", help="MD5 hash");   sm.add_argument("text")
    sh = sub.add_parser("sha256", help="SHA256 hash"); sh.add_argument("text")

    # base64
    sb = sub.add_parser("b64enc", help="Base64 encode"); sb.add_argument("text")
    sbd = sub.add_parser("b64dec", help="Base64 decode"); sbd.add_argument("text")

    # diceware / uuid / color
    sd = sub.add_parser("diceware", help="Diceware passphrase"); sd.add_argument("--words", "-w", type=int, default=6)
    suid = sub.add_parser("uuid", help="Generate UUID")
    scol = sub.add_parser("color", help="Generate HEX color")

    # history
    shis = sub.add_parser("history", help="Show history")
    sexp = sub.add_parser("export", help="Export history to file"); sexp.add_argument("--out", "-o", default="security_toolkit_history.txt")

    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return p

def run_args(args):
    if args.cmd == "password":
        pw = gen_password(
            args.length,
            upper=not args.no_upper,
            lower=not args.no_lower,
            digits=not args.no_digits,
            symbols=not args.no_symbols
        )
        print(pw); add_history("Password", pw)

    elif args.cmd == "strength":
        label, entropy, _ = password_strength(args.password)
        print(f"{label} | Entropy: {entropy} bits"); add_history("Strength", f"{label} ({entropy} bits)")

    elif args.cmd == "token":
        t = rand_token(args.length); print(t); add_history("Token", t)

    elif args.cmd == "pin":
        p = rand_pin(args.length); print(p); add_history("PIN", p)

    elif args.cmd == "username":
        u = rand_username(args.length); print(u); add_history("Username", u)

    elif args.cmd == "email":
        e = rand_email(args.name); print(e); add_history("Email", e)

    elif args.cmd == "md5":
        h = md5_hash(args.text); print(h); add_history("MD5", h)

    elif args.cmd == "sha256":
        h = sha256_hash(args.text); print(h); add_history("SHA256", h)

    elif args.cmd == "b64enc":
        out = b64_encode(args.text); print(out); add_history("Base64 enc", out)

    elif args.cmd == "b64dec":
        out = b64_decode(args.text); print("Invalid Base64" if out is None else out); add_history("Base64 dec", out or "Invalid")

    elif args.cmd == "diceware":
        ph = diceware(args.words); print(ph); add_history("Diceware", ph)

    elif args.cmd == "uuid":
        u = new_uuid(); print(u); add_history("UUID", u)

    elif args.cmd == "color":
        c = color_hex(); print(c); add_history("Color HEX", c)

    elif args.cmd == "history":
        print_history()

    elif args.cmd == "export":
        export_history(args.out)

    else:
        # no subcommand -> enter interactive menu
        menu_loop()

# ---------------- Main ----------------
if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    # (colors already auto-detected; --no-color just avoids warning)
    run_args(args)
