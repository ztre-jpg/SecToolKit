# Security Toolkit — compact, animated, with history, QR tool, and theme color picker
# pip install customtkinter
# (Optional for QR tool) pip install qrcode[pil] pillow

import customtkinter as ctk
from tkinter import messagebox, filedialog, colorchooser
import os, hashlib, random, string, base64, uuid, re, math

APP_TITLE = "Security Toolkit"
CRED_FILE = "credentials.txt"

# -------------------- Credential utils --------------------
def _sha256(s: str) -> str: return hashlib.sha256(s.encode()).hexdigest()
def save_credentials(username: str, password: str) -> None:
    with open(CRED_FILE, "w", encoding="utf-8") as f:
        f.write(username.strip() + "\n" + _sha256(password.strip()) + "\n")
def load_credentials():
    if not os.path.exists(CRED_FILE): return None, None
    with open(CRED_FILE, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f.readlines()]
    return (lines[0], lines[1]) if len(lines) >= 2 else (None, None)
def validate_login(username: str, password: str) -> bool:
    u, h = load_credentials()
    return bool(u and h and u == username.strip() and h == _sha256(password.strip()))

# -------------------- Generators & helpers --------------------
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

def strength_info(pw: str):
    score = 0
    if len(pw) >= 8: score += 1
    if re.search(r"[A-Z]", pw): score += 1
    if re.search(r"[a-z]", pw): score += 1
    if re.search(r"[0-9]", pw): score += 1
    if re.search(r"[^A-Za-z0-9]", pw): score += 1
    labels = ["Very Weak","Weak","Moderate","Strong","Very Strong","Excellent"]
    label = labels[min(score, 5)]
    charset = 0
    if re.search(r"[A-Z]", pw): charset += 26
    if re.search(r"[a-z]", pw): charset += 26
    if re.search(r"[0-9]", pw): charset += 10
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
def b64_enc(s): return base64.b64encode(s.encode()).decode()
def b64_dec(s):
    try: return base64.b64decode(s.encode()).decode()
    except Exception: return "Invalid Base64"
def diceware(n=6):
    words = ["apple","basic","crane","delta","ember","folio","grape","harbor","ionic","jungle",
             "kettle","lemon","mango","nebula","onyx","panda","quartz","raven","sigma","tango",
             "ultra","vivid","willow","xenon","yonder","zephyr"]
    n = max(3, min(12, int(n)))
    return " ".join(random.choice(words) for _ in range(n))
def color_hex(): return "#{:06X}".format(random.randint(0, 0xFFFFFF))
def new_uuid(): return str(uuid.uuid4())

# -------------------- App with slide navigation + theme + history --------------------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.title(APP_TITLE)
        self.geometry("960x600")
        self.minsize(860, 520)

        self.container = ctk.CTkFrame(self, corner_radius=0)
        self.container.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.current = None

        self.accent = "#1f6aa5"
        self.history = []  # list of (tool, value)

        self.show_login()

    # slide transition
    def _slide_to(self, frame: ctk.CTkFrame, direction="left"):
        self.update_idletasks()
        w = max(1, self.container.winfo_width())
        if self.current is not None:
            self.current.place(in_=self.container, x=0, y=0, relwidth=1, relheight=1)

        start_x = w if direction == "left" else -w
        frame.place(in_=self.container, x=start_x, y=0, relwidth=1, relheight=1)
        steps, delay = 16, 8
        for i in range(steps + 1):
            t = i / steps
            nx = int((1 - t) * start_x)
            ox = int((-t) * start_x)
            frame.place_configure(x=nx)
            if self.current is not None:
                self.current.place_configure(x=ox)
            self.update_idletasks()
            self.after(delay)

        if self.current is not None:
            self.current.place_forget()
            self.current.destroy()
        frame.place_forget()
        frame.pack(in_=self.container, fill="both", expand=True)
        self.current = frame

    def show_login(self): self._slide_to(LoginPage(self), direction="right")
    def show_home(self):  self._slide_to(HomePage(self), direction="left")
    def show_tool(self, page_cls): self._slide_to(page_cls(self), direction="left")
    def show_history(self): self._slide_to(HistoryPage(self), direction="left")
    def show_settings(self): self._slide_to(SettingsPage(self), direction="left")

    def add_history(self, tool_name, value):
        if value:
            self.history.append((tool_name, str(value)))
            # keep last 200 entries
            if len(self.history) > 200:
                self.history = self.history[-200:]

# -------------------- Reusable bits --------------------
def copy_to_clipboard(widget, root):
    text = widget.get()
    root.clipboard_clear()
    root.clipboard_append(text)
    messagebox.showinfo("Copied", "Output copied to clipboard!")

class Collapsible(ctk.CTkFrame):
    def __init__(self, master, title="Section", accent="#1f6aa5"):
        super().__init__(master)
        self.columnconfigure(0, weight=1)
        self.accent = accent
        self.open = True
        self.header = ctk.CTkButton(self, text=f"▼  {title}", fg_color=self.accent, hover_color="#14537b",
                                    command=self.toggle)
        self.header.grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        self.body = ctk.CTkFrame(self, corner_radius=10)
        self.body.grid(row=1, column=0, sticky="ew", padx=4, pady=(0,6))
    def toggle(self):
        self.open = not self.open
        text = self.header.cget("text")
        self.header.configure(text=("▼  " if self.open else "▶  ") + text[3:])
        if self.open:
            self.body.grid(row=1, column=0, sticky="ew", padx=4, pady=(0,6))
        else:
            self.body.grid_forget()
    def set_accent(self, color):
        self.accent = color
        self.header.configure(fg_color=self.accent)

# -------------------- Login Page --------------------
class LoginPage(ctk.CTkFrame):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        bg = ctk.CTkCanvas(self, width=960, height=600, highlightthickness=0)
        bg.grid(row=0, column=0, sticky="nsew")
        bg.create_rectangle(0, 0, 960, 600, fill="#0f1624", outline="")
        bg.create_oval(-200, -180, 480, 600, fill="#1b2540", outline="")
        bg.create_oval(720, -120, 1200, 480, fill="#22335d", outline="")

        card = ctk.CTkFrame(self, corner_radius=14)
        card.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(card, text="🔐  Security Toolkit", font=ctk.CTkFont(size=26, weight="bold")).pack(pady=(18, 8))
        self.user = ctk.CTkEntry(card, width=260, placeholder_text="Username")
        self.user.pack(pady=6)
        self.pw = ctk.CTkEntry(card, width=260, placeholder_text="Password", show="•")
        self.pw.pack(pady=6)
        self.show_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(card, text="Show password", variable=self.show_var,
                        command=lambda: self.pw.configure(show="" if self.show_var.get() else "•")).pack(pady=(0,8))
        row = ctk.CTkFrame(card, fg_color="transparent"); row.pack(pady=8)
        ctk.CTkButton(row, text="Login", width=120, command=self._login).grid(row=0, column=0, padx=6)
        ctk.CTkButton(row, text="Register", width=120, fg_color="#1f6aa5", hover_color="#14537b",
                      command=self.register_user).grid(row=0, column=1, padx=6)
        u, h = load_credentials()
        if u and h: self.user.insert(0, u)

    def _login(self):
        if validate_login(self.user.get(), self.pw.get()):
            self.app.show_home()
        else:
            messagebox.showerror("Login failed", "Invalid username or password.")

    def register_user(self):
        u, p = self.user.get().strip(), self.pw.get()
        if not u or not p:
            messagebox.showerror("Missing info", "Please enter username and password.")
            return
        save_credentials(u, p)
        messagebox.showinfo("Success", "Registration complete. You can now log in.")

# -------------------- Home Page (toolbar + categories + search) --------------------
class HomePage(ctk.CTkFrame):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self._build()

    def _build(self):
        self.rowconfigure(2, weight=1)
        self.columnconfigure(0, weight=1)

        # Top toolbar
        toolbar = ctk.CTkFrame(self, corner_radius=0)
        toolbar.grid(row=0, column=0, sticky="ew")
        toolbar.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(toolbar, text="🏠  Home", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, padx=14, pady=8, sticky="w")

        right = ctk.CTkFrame(toolbar, fg_color="transparent"); right.grid(row=0, column=1, padx=8, pady=6, sticky="e")
        mode_var = ctk.StringVar(value="Dark")
        def set_mode(v): ctk.set_appearance_mode("dark" if v=="Dark" else "light")
        ctk.CTkSegmentedButton(right, values=["Dark","Light"], variable=mode_var, command=set_mode).grid(row=0, column=0, padx=6)
        ctk.CTkButton(right, text="🕘 History", width=90, command=self.app.show_history).grid(row=0, column=1, padx=6)
        ctk.CTkButton(right, text="🎨 Settings", width=90, command=self.app.show_settings).grid(row=0, column=2, padx=6)
        ctk.CTkButton(right, text="🔓 Logout", width=90, command=self.app.show_login).grid(row=0, column=3, padx=6)

        # Search bar
        search_row = ctk.CTkFrame(self, fg_color="transparent")
        search_row.grid(row=1, column=0, sticky="ew", padx=14, pady=(6,6))
        self.search = ctk.CTkEntry(search_row, placeholder_text="Search tools…", height=36)
        self.search.pack(fill="x", expand=True)
        self.search.bind("<KeyRelease>", self._refresh)

        # Content area
        content = ctk.CTkScrollableFrame(self, corner_radius=10)
        content.grid(row=2, column=0, sticky="nsew", padx=12, pady=(6,12))

        # Categories
        self.security = Collapsible(content, "Security", accent=self.app.accent)
        self.encoding = Collapsible(content, "Encoding", accent=self.app.accent)
        self.utility  = Collapsible(content, "Utility",  accent=self.app.accent)
        for sec in (self.security, self.encoding, self.utility):
            sec.pack(fill="x", padx=4, pady=4)

        self.tool_map = {
            "Password Generator": PasswordGeneratorPage,
            "Password Strength Checker": PasswordStrengthPage,
            "Token Generator": TokenGeneratorPage,
            "PIN Generator": PinGeneratorPage,
            "MD5 Hash": MD5Page,
            "SHA256 Hash": SHA256Page,
            "Base64 Encode/Decode": Base64Page,
            "Diceware Passphrase": DicewarePage,
            "QRCode Generator": QRCodePage,  # NEW
            "Username Generator": UsernameGeneratorPage,
            "Email Generator": EmailGeneratorPage,
            "UUID Generator": UUIDPage,
            "Color Code Generator": ColorPage,
        }
        self._security_tools = [
            "Password Generator", "Password Strength Checker", "Token Generator", "PIN Generator",
            "MD5 Hash", "SHA256 Hash", "Diceware Passphrase", "QRCode Generator"
        ]
        self._encoding_tools = ["Base64 Encode/Decode"]
        self._utility_tools  = ["Username Generator", "Email Generator", "UUID Generator", "Color Code Generator"]

        self._refresh()

    def _add_button(self, parent, name, page_cls):
        btn = ctk.CTkButton(parent, text=name, height=36, width=780,
                            fg_color=self.app.accent, hover_color="#14537b",
                            command=lambda c=page_cls: self.app.show_tool(c))
        btn.pack(padx=8, pady=4)

    def _refresh(self, *_):
        q = self.search.get().lower().strip()
        for sec in (self.security, self.encoding, self.utility):
            for w in sec.body.winfo_children(): w.destroy()
            sec.set_accent(self.app.accent)
        for n in self._security_tools:
            if q in n.lower(): self._add_button(self.security.body, n, self.tool_map[n])
        for n in self._encoding_tools:
            if q in n.lower(): self._add_button(self.encoding.body, n, self.tool_map[n])
        for n in self._utility_tools:
            if q in n.lower(): self._add_button(self.utility.body, n, self.tool_map[n])

# -------------------- History Page --------------------
class HistoryPage(ctk.CTkFrame):
    def __init__(self, app: App):
        super().__init__(app); self.app = app
        self._build()

    def _build(self):
        bar = ctk.CTkFrame(self, corner_radius=0); bar.pack(fill="x")
        ctk.CTkLabel(bar, text="🕘  History", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(bar, text="← Home", width=90, command=self.app.show_home).pack(side="right", padx=10, pady=8)

        body = ctk.CTkFrame(self, corner_radius=10); body.pack(fill="both", expand=True, padx=14, pady=(6,12))
        self.text = ctk.CTkTextbox(body, width=820, height=420)
        self.text.pack(padx=10, pady=10)
        self.text.insert("1.0", self._history_as_text())
        self.text.configure(state="disabled")

        btns = ctk.CTkFrame(body, fg_color="transparent"); btns.pack(pady=6)
        ctk.CTkButton(btns, text="Export to TXT", width=140, command=self._export).grid(row=0, column=0, padx=6)
        ctk.CTkButton(btns, text="Clear History", width=140, fg_color="#8a1f1f",
                      hover_color="#5d1414", command=self._clear).grid(row=0, column=1, padx=6)

    def _history_as_text(self):
        if not self.app.history: return "No history yet."
        lines = []
        for i, (tool, value) in enumerate(self.app.history, 1):
            lines.append(f"{i:02d}. [{tool}] {value}")
        return "\n".join(lines)

    def _refresh_box(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", self._history_as_text())
        self.text.configure(state="disabled")

    def _export(self):
        if not self.app.history:
            messagebox.showinfo("Export", "History is empty.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".txt",
                                         filetypes=[("Text file","*.txt")],
                                         initialfile="security_toolkit_history.txt")
        if not f: return
        with open(f, "w", encoding="utf-8") as out:
            out.write(self._history_as_text())
        messagebox.showinfo("Export", f"History exported to:\n{f}")

    def _clear(self):
        if messagebox.askyesno("Clear History", "Delete all history entries?"):
            self.app.history.clear()
            self._refresh_box()

# -------------------- Settings Page (Theme color picker) --------------------
class SettingsPage(ctk.CTkFrame):
    def __init__(self, app: App):
        super().__init__(app); self.app = app
        self._build()

    def _build(self):
        bar = ctk.CTkFrame(self, corner_radius=0); bar.pack(fill="x")
        ctk.CTkLabel(bar, text="🎨  Settings", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(bar, text="← Home", width=90, command=self.app.show_home).pack(side="right", padx=10, pady=8)

        body = ctk.CTkFrame(self, corner_radius=10); body.pack(fill="both", expand=True, padx=14, pady=(6,12))
        ctk.CTkLabel(body, text="Accent Color", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(16,6))
        preview = ctk.CTkFrame(body, width=180, height=36, corner_radius=8, fg_color=self.app.accent)
        preview.pack(pady=6)
        preview.pack_propagate(False)

        def pick_color():
            rgb, hexcol = colorchooser.askcolor(initialcolor=self.app.accent, title="Choose Accent Color")
            if hexcol:
                self.app.accent = hexcol
                preview.configure(fg_color=hexcol)
                # simply go back home to refresh colors
                self.app.show_home()

        ctk.CTkButton(body, text="Pick Color…", width=140, command=pick_color).pack(pady=8)
        ctk.CTkLabel(body, text="Tip: Accent applies to category headers and tool buttons on Home.",
                     wraplength=720, justify="center").pack(pady=(6,12))

# -------------------- Base Tool Template --------------------
class BaseTool(ctk.CTkFrame):
    title_text = "Tool"
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self._header()
        self.body = ctk.CTkFrame(self, corner_radius=10)
        self.body.pack(fill="both", expand=True, padx=14, pady=(6,12))

    def _header(self):
        bar = ctk.CTkFrame(self, corner_radius=0)
        bar.pack(fill="x")
        ctk.CTkLabel(bar, text=f"🛠️  {self.title_text}", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(bar, text="← Home", width=90, command=self.app.show_home).pack(side="right", padx=10, pady=8)

    def _row_entry(self, parent, label, placeholder="", width=520, secret=False):
        row = ctk.CTkFrame(parent, fg_color="transparent"); row.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(row, text=label, width=140, anchor="w").pack(side="left")
        ent = ctk.CTkEntry(row, placeholder_text=placeholder, width=width, show=("•" if secret else ""))
        ent.pack(side="left", padx=6)
        return ent

    def _row_output(self, parent, label, width=520):
        row = ctk.CTkFrame(parent, fg_color="transparent"); row.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(row, text=label, width=140, anchor="w").pack(side="left")
        ent = ctk.CTkEntry(row, width=width); ent.pack(side="left", padx=6)
        ctk.CTkButton(row, text="📋 Copy", width=70, command=lambda: copy_to_clipboard(ent, self)).pack(side="left", padx=6)
        return ent

# -------------------- Tools --------------------
class PasswordGeneratorPage(BaseTool):
    title_text = "Password Generator"
    def __init__(self, app):
        super().__init__(app)
        opt = ctk.CTkFrame(self.body, fg_color="transparent"); opt.pack(pady=(10,2))
        self.len_var = ctk.IntVar(value=16)
        ctk.CTkLabel(opt, text="Length").grid(row=0, column=0, padx=6, pady=4, sticky="e")
        ctk.CTkEntry(opt, textvariable=self.len_var, width=80).grid(row=0, column=1, padx=6)
        self.u = ctk.BooleanVar(value=True); self.l = ctk.BooleanVar(value=True)
        self.d = ctk.BooleanVar(value=True); self.s = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(opt, text="Uppercase", variable=self.u).grid(row=0, column=2, padx=6)
        ctk.CTkCheckBox(opt, text="Lowercase", variable=self.l).grid(row=0, column=3, padx=6)
        ctk.CTkCheckBox(opt, text="Digits",    variable=self.d).grid(row=0, column=4, padx=6)
        ctk.CTkCheckBox(opt, text="Symbols",   variable=self.s).grid(row=0, column=5, padx=6)

        self.out = self._row_output(self.body, "Password")
        self.str_lbl = ctk.CTkLabel(self.body, text="Strength: -"); self.str_lbl.pack(pady=(2,10))
        ctk.CTkButton(self.body, text="Generate", width=140, command=self._make).pack()

    def _make(self):
        ln = self.len_var.get()
        pw = gen_password(ln, self.u.get(), self.l.get(), self.d.get(), self.s.get())
        self.out.delete(0,"end"); self.out.insert(0, pw)
        label, entropy, score = strength_info(pw)
        self.str_lbl.configure(text=f"Strength: {label} | Entropy: {entropy} bits")
        self.app.add_history("Password", pw)

class PasswordStrengthPage(BaseTool):
    title_text = "Password Strength Checker"
    def __init__(self, app):
        super().__init__(app)
        self.inp = self._row_entry(self.body, "Password", "enter password", secret=True)
        self.out = self._row_output(self.body, "Result")
        ctk.CTkButton(self.body, text="Check", width=120, command=self._check).pack(pady=6)

    def _check(self):
        label, entropy, score = strength_info(self.inp.get())
        res = f"{label}  |  Entropy: {entropy} bits"
        self.out.delete(0,"end"); self.out.insert(0, res)
        self.app.add_history("Strength", res)

class TokenGeneratorPage(BaseTool):
    title_text = "Token Generator"
    def __init__(self, app):
        super().__init__(app)
        self.len_e = self._row_entry(self.body, "Length", "32", width=120)
        self.out = self._row_output(self.body, "Token")
        ctk.CTkButton(self.body, text="Generate", width=120, command=self._go).pack(pady=6)
    def _go(self):
        try: ln = int((self.len_e.get() or "32"))
        except ValueError: ln = 32
        val = rand_token(ln)
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("Token", val)

class PinGeneratorPage(BaseTool):
    title_text = "PIN Generator"
    def __init__(self, app):
        super().__init__(app)
        self.len_e = self._row_entry(self.body, "Length", "6", width=120)
        self.out = self._row_output(self.body, "PIN")
        ctk.CTkButton(self.body, text="Generate", width=120, command=self._go).pack(pady=6)
    def _go(self):
        try: ln = int((self.len_e.get() or "6"))
        except ValueError: ln = 6
        val = rand_pin(ln)
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("PIN", val)

class UsernameGeneratorPage(BaseTool):
    title_text = "Username Generator"
    def __init__(self, app):
        super().__init__(app)
        self.len_e = self._row_entry(self.body, "Length", "8", width=120)
        self.out = self._row_output(self.body, "Username")
        ctk.CTkButton(self.body, text="Generate", width=120, command=self._go).pack(pady=6)
    def _go(self):
        try: ln = int((self.len_e.get() or "8"))
        except ValueError: ln = 8
        val = rand_username(ln)
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("Username", val)

class EmailGeneratorPage(BaseTool):
    title_text = "Email Generator"
    def __init__(self, app):
        super().__init__(app)
        self.name_e = self._row_entry(self.body, "Local-part", "optional name", width=240)
        self.out = self._row_output(self.body, "Email")
        ctk.CTkButton(self.body, text="Generate", width=120, command=self._go).pack(pady=6)
    def _go(self):
        val = rand_email(self.name_e.get())
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("Email", val)

class MD5Page(BaseTool):
    title_text = "MD5 Hash"
    def __init__(self, app):
        super().__init__(app)
        self.inp = self._row_entry(self.body, "Input", "text to hash")
        self.out = self._row_output(self.body, "MD5")
        ctk.CTkButton(self.body, text="Hash", width=120, command=self._go).pack(pady=6)
    def _go(self):
        val = md5_hash(self.inp.get())
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("MD5", val)

class SHA256Page(BaseTool):
    title_text = "SHA256 Hash"
    def __init__(self, app):
        super().__init__(app)
        self.inp = self._row_entry(self.body, "Input", "text to hash")
        self.out = self._row_output(self.body, "SHA256")
        ctk.CTkButton(self.body, text="Hash", width=120, command=self._go).pack(pady=6)
    def _go(self):
        val = sha256_hash(self.inp.get())
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("SHA256", val)

class Base64Page(BaseTool):
    title_text = "Base64 Encode / Decode"
    def __init__(self, app):
        super().__init__(app)
        self.inp = self._row_entry(self.body, "Input", "text to encode/decode")
        self.out = self._row_output(self.body, "Result")
        row = ctk.CTkFrame(self.body, fg_color="transparent"); row.pack(pady=6)
        ctk.CTkButton(row, text="Encode", width=120, command=self._enc).grid(row=0, column=0, padx=6)
        ctk.CTkButton(row, text="Decode", width=120, command=self._dec).grid(row=0, column=1, padx=6)
    def _enc(self):
        val = b64_enc(self.inp.get())
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("Base64 Encode", val)
    def _dec(self):
        val = b64_dec(self.inp.get())
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("Base64 Decode", val)

class DicewarePage(BaseTool):
    title_text = "Diceware Passphrase"
    def __init__(self, app):
        super().__init__(app)
        self.n_e = self._row_entry(self.body, "Words", "6", width=120)
        self.out = self._row_output(self.body, "Passphrase")
        ctk.CTkButton(self.body, text="Generate", width=120, command=self._go).pack(pady=6)
    def _go(self):
        try: n = int((self.n_e.get() or "6"))
        except ValueError: n = 6
        val = diceware(n)
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("Diceware", val)

class UUIDPage(BaseTool):
    title_text = "UUID Generator"
    def __init__(self, app):
        super().__init__(app)
        self.out = self._row_output(self.body, "UUID")
        ctk.CTkButton(self.body, text="Generate", width=120, command=self._go).pack(pady=6)
    def _go(self):
        val = new_uuid()
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("UUID", val)

class ColorPage(BaseTool):
    title_text = "Color Code Generator"
    def __init__(self, app):
        super().__init__(app)
        self.out = self._row_output(self.body, "HEX")
        ctk.CTkButton(self.body, text="Generate", width=120, command=self._go).pack(pady=6)
    def _go(self):
        val = color_hex()
        self.out.delete(0,"end"); self.out.insert(0, val)
        self.app.add_history("Color HEX", val)

class QRCodePage(BaseTool):
    title_text = "QRCode Generator"
    def __init__(self, app):
        super().__init__(app)
        # Try import qrcode and PIL
        try:
            import qrcode  # type: ignore
            from PIL import Image, ImageTk  # noqa
            self.qrcode_ok = True
        except Exception:
            self.qrcode_ok = False

        self.inp = self._row_entry(self.body, "Text/URL", "content to encode")
        self.png_path = None

        row = ctk.CTkFrame(self.body, fg_color="transparent"); row.pack(pady=6)
        ctk.CTkButton(row, text="Generate", width=120, command=self._make).grid(row=0, column=0, padx=6)
        ctk.CTkButton(row, text="Save PNG", width=120, command=self._save).grid(row=0, column=1, padx=6)

        self.info = ctk.CTkLabel(self.body, text="")
        self.info.pack(pady=(2,10))

        self.preview = ctk.CTkLabel(self.body, text="(preview appears here)")
        self.preview.pack(pady=6)

        if not self.qrcode_ok:
            self.info.configure(text="To enable QR generation:\n  pip install qrcode[pil] pillow", text_color="#ffb347")

    def _make(self):
        if not self.qrcode_ok:
            messagebox.showwarning("Missing dependency", "Install 'qrcode' and 'pillow' to use this tool:\n\npip install qrcode[pil] pillow")
            return
        import qrcode
        from PIL import Image, ImageTk
        data = self.inp.get().strip()
        if not data:
            messagebox.showerror("Error", "Please enter content for the QR code.")
            return
        img = qrcode.make(data)
        img = img.resize((220, 220))
        self._pil_img = img  # keep ref
        self._tk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(220, 220))
        self.preview.configure(image=self._tk_img, text="")
        self.info.configure(text="QR generated. Click 'Save PNG' to export.")
        self.app.add_history("QR", data)

    def _save(self):
        if not self.qrcode_ok:
            return
        if not hasattr(self, "_pil_img"):
            messagebox.showinfo("Save", "Generate a QR first.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".png",
                                         filetypes=[("PNG Image","*.png")],
                                         initialfile="qrcode.png")
        if not f: return
        self._pil_img.save(f)
        messagebox.showinfo("Saved", f"Saved to:\n{f}")

# -------------------- Run --------------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
