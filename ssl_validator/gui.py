"""Tkinter user interface for the SSL certificate validator (macOS-inspired look)."""

from __future__ import annotations

import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter import font as tkfont

from . import certcore as cc

APP_TITLE = "SSL Certificate Validator"

FILE_TYPES = [
    ("Certificate files", "*.pem *.crt *.cer *.cert *.der *.p7b *.p7c *.pfx *.p12 *.ca-bundle *.bundle *.chain"),
    ("All files", "*.*"),
]
KEY_TYPES = [("Private keys", "*.key *.pem *.pfx *.p12"), ("All files", "*.*")]

# ---------------------------------------------------------------------------
# Look & feel (light macOS palette)
# ---------------------------------------------------------------------------

BG = "#f5f5f7"          # window background
CARD = "#ffffff"        # card background
BORDER = "#e3e3e8"      # hairline borders
TEXT = "#1d1d1f"        # primary text
MUTED = "#6e6e73"       # secondary text
ACCENT = "#0071e3"      # Apple blue
ACCENT_HOVER = "#0077ed"
BTN = "#e8e8ed"         # secondary button
BTN_HOVER = "#dcdce1"
SELECTED = "#dbe8fb"    # selected row
DIFF = "#fff4d6"        # differing compare rows

SEV_FG = {cc.OK: "#1e8e3e", cc.INFO: "#0b57d0", cc.WARN: "#b25e00", cc.ERROR: "#d70015"}
SEV_BG = {cc.OK: "#eaf6ec", cc.INFO: "#eaf1fd", cc.WARN: "#fff5e5", cc.ERROR: "#fdecee"}
SEV_ICON = {cc.OK: "✓", cc.INFO: "i", cc.WARN: "!", cc.ERROR: "✕"}
SEV_LABEL = {cc.OK: "Passed", cc.INFO: "Info", cc.WARN: "Warning", cc.ERROR: "Error"}

UI_FONTS = ["SF Pro Text", "SF Pro Display", ".AppleSystemUIFont", "Helvetica Neue", "Inter",
            "Segoe UI Variable Text", "Segoe UI", "Helvetica", "Arial"]
MONO_FONTS = ["SF Mono", "Menlo", "Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Courier New"]

F: dict[str, tuple] = {}  # filled by init_style()


def _pick(root: tk.Misc, prefs: list[str]) -> str:
    available = set(tkfont.families(root))
    for name in prefs:
        if name in available:
            return name
    return "TkDefaultFont"


def init_style(root: tk.Tk) -> None:
    ui = _pick(root, UI_FONTS)
    mono = _pick(root, MONO_FONTS)
    F.update(
        title=(ui, 18, "bold"),
        subtitle=(ui, 10),
        banner=(ui, 14, "bold"),
        section=(ui, 12, "bold"),
        body=(ui, 10),
        body_bold=(ui, 10, "bold"),
        small=(ui, 9),
        button=(ui, 10),
        button_bold=(ui, 10, "bold"),
        cn=(ui, 15, "bold"),
        mono=(mono, 10),
    )
    root.option_add("*Font", F["body"])
    root.configure(bg=BG)

    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=TEXT, font=F["body"])

    row_h = int(tkfont.Font(root, font=F["body"]).metrics("linespace") * 2)
    s.configure("Mac.Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                rowheight=row_h, borderwidth=0, relief="flat", font=F["body"])
    s.map("Mac.Treeview", background=[("selected", SELECTED)], foreground=[("selected", TEXT)])
    s.layout("Mac.Treeview", [("Mac.Treeview.treearea", {"sticky": "nswe"})])
    s.configure("Mac.Treeview.Heading", background=CARD, foreground=MUTED, font=F["small"] + ("bold",),
                relief="flat", borderwidth=0, padding=(6, 6))
    s.map("Mac.Treeview.Heading", background=[("active", CARD)], relief=[("active", "flat")])

    s.layout("Mac.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
        "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})], "sticky": "ns"})])
    s.configure("Mac.Vertical.TScrollbar", troughcolor=CARD, background="#c7c7cc", bordercolor=CARD,
                lightcolor="#c7c7cc", darkcolor="#c7c7cc", gripcount=0, width=8, relief="flat")
    s.map("Mac.Vertical.TScrollbar", background=[("active", "#a1a1a6")])

    s.configure("Mac.TCheckbutton", background=BG, foreground=TEXT, font=F["body"], focuscolor=BG,
                indicatorbackground=CARD, indicatorforeground=ACCENT, padding=(0, 2))
    s.map("Mac.TCheckbutton", background=[("active", BG)], indicatorbackground=[("selected", CARD)])

    s.configure("Mac.TCombobox", fieldbackground=CARD, background=CARD, foreground=TEXT,
                bordercolor=BORDER, lightcolor=CARD, darkcolor=CARD, arrowcolor=MUTED, padding=(8, 4))
    s.map("Mac.TCombobox", fieldbackground=[("readonly", CARD)], selectbackground=[("readonly", CARD)],
          selectforeground=[("readonly", TEXT)])

    s.configure("TPanedwindow", background=BG)
    s.configure("Sash", sashthickness=12, gripcount=0, background=BG, lightcolor=BG, bordercolor=BG)


# ---------------------------------------------------------------------------
# Small custom widgets
# ---------------------------------------------------------------------------

def round_rect(c: tk.Canvas, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, splinesteps=24, **kw)


def _bg_of(w: tk.Misc) -> str:
    try:
        return w.cget("bg")
    except tk.TclError:
        return BG


class RoundButton(tk.Canvas):
    """A rounded, flat button (primary = blue, secondary = light gray)."""

    def __init__(self, master, text: str, command, kind: str = "secondary", height: int = 32):
        font = F["button_bold"] if kind == "primary" else F["button"]
        w = tkfont.Font(font=font).measure(text) + 32
        super().__init__(master, width=w, height=height, bg=_bg_of(master), highlightthickness=0, bd=0,
                         cursor="hand2")
        self.text, self.command, self.kind, self.font = text, command, kind, font
        self.w, self.h = w, height
        self._hover = False
        self._draw()
        self.bind("<Enter>", lambda e: self._set_hover(True))
        self.bind("<Leave>", lambda e: self._set_hover(False))
        self.bind("<ButtonRelease-1>", self._click)

    def _set_hover(self, v):
        self._hover = v
        self._draw()

    def _click(self, e):
        if 0 <= e.x <= self.w and 0 <= e.y <= self.h and self.command:
            self.command()

    def _draw(self):
        self.delete("all")
        if self.kind == "primary":
            fill, fg = (ACCENT_HOVER if self._hover else ACCENT), "#ffffff"
        else:
            fill, fg = (BTN_HOVER if self._hover else BTN), TEXT
        round_rect(self, 1, 1, self.w - 1, self.h - 1, 9, fill=fill, outline="")
        self.create_text(self.w / 2, self.h / 2, text=self.text, fill=fg, font=self.font)


class Segmented(tk.Canvas):
    """macOS-style segmented control."""

    def __init__(self, master, options: list[str], command, seg_w: int = 150, height: int = 34):
        self.options, self.command, self.seg_w, self.h = options, command, seg_w, height
        self.w = seg_w * len(options) + 6
        super().__init__(master, width=self.w, height=height, bg=_bg_of(master), highlightthickness=0, bd=0,
                         cursor="hand2")
        self.index = 0
        self._draw()
        self.bind("<ButtonRelease-1>", self._click)

    def select(self, i: int):
        self.index = i
        self._draw()
        self.command(i)

    def _click(self, e):
        i = max(0, min(len(self.options) - 1, int((e.x - 3) // self.seg_w)))
        if i != self.index:
            self.select(i)

    def _draw(self):
        self.delete("all")
        round_rect(self, 0, 0, self.w - 1, self.h - 1, 10, fill=BTN, outline="")
        x = 3 + self.index * self.seg_w
        round_rect(self, x, 3, x + self.seg_w, self.h - 4, 8, fill=CARD, outline="#d2d2d7")
        for i, opt in enumerate(self.options):
            cx = 3 + i * self.seg_w + self.seg_w / 2
            sel = i == self.index
            self.create_text(cx, self.h / 2, text=opt, font=F["button_bold"] if sel else F["button"],
                             fill=TEXT if sel else MUTED)


def card(parent, title: str | None = None):
    """White card with hairline border. Returns (outer, header, body)."""
    outer = tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER, highlightcolor=BORDER)
    header = None
    if title:
        header = tk.Frame(outer, bg=CARD)
        header.pack(fill="x", padx=16, pady=(12, 6))
        tk.Label(header, text=title, font=F["section"], bg=CARD, fg=TEXT).pack(side="left")
    body = tk.Frame(outer, bg=CARD)
    body.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    return outer, header, body


def autohide(sb: ttk.Scrollbar):
    """yscrollcommand that only shows the scrollbar when content overflows (like macOS)."""

    def _set(lo, hi):
        if float(lo) <= 0.0 and float(hi) >= 1.0:
            sb.pack_forget()
        elif not sb.winfo_ismapped():
            sb.pack(side="left", fill="y", padx=(4, 0))
        sb.set(lo, hi)

    return _set


def scrolled_tree(parent, **kw) -> ttk.Treeview:
    tree = ttk.Treeview(parent, style="Mac.Treeview", **kw)
    sb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview, style="Mac.Vertical.TScrollbar")
    tree.configure(yscrollcommand=autohide(sb))
    tree.pack(side="left", fill="both", expand=True)
    for sev in SEV_BG:
        tree.tag_configure(sev, background=SEV_BG[sev], foreground=TEXT)
        tree.tag_configure("fg_" + sev, foreground=SEV_FG[sev])
    tree.tag_configure("muted", foreground=MUTED)
    tree.tag_configure("diff", background=DIFF)
    tree.tag_configure("bold", font=F["body_bold"])
    return tree


def checkbox(parent, text, var, command=None):
    return ttk.Checkbutton(parent, text=text, variable=var, command=command, style="Mac.TCheckbutton")


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

class PasswordCache:
    """Asks for PKCS#12 / encrypted key passwords once per file."""

    def __init__(self, root: tk.Misc):
        self.root = root
        self.passwords: dict[str, str] = {}

    def _ask(self, path, retry):
        prompt = "Wrong password. Password for" if retry else "Password for"
        return simpledialog.askstring(APP_TITLE, f"{prompt}\n{os.path.basename(path)}:", show="•", parent=self.root)

    def load_certs(self, path: str) -> list[cc.CertInfo]:
        pw = self.passwords.get(path)
        while True:
            try:
                certs = cc.load_certificates(path, pw)
                if pw is not None:
                    self.passwords[path] = pw
                return certs
            except cc.PasswordRequired:
                pw = self._ask(path, pw is not None)
                if pw is None:
                    raise

    def load_key(self, path: str):
        pw = self.passwords.get(path)
        ext = os.path.splitext(path.lower())[1]
        while True:
            try:
                if ext in (".pfx", ".p12"):
                    key = cc.load_pkcs12_key(path, pw)
                    if key is None:
                        raise cc.PasswordRequired("")
                else:
                    key = cc.load_private_key(path, pw)
                if pw is not None:
                    self.passwords[path] = pw
                return key
            except cc.PasswordRequired:
                pw = self._ask(path, pw is not None)
                if pw is None:
                    raise


# ---------------------------------------------------------------------------
# Validate page
# ---------------------------------------------------------------------------

class ValidatePage(tk.Frame):
    def __init__(self, master, pw: PasswordCache):
        super().__init__(master, bg=BG)
        self.pw = pw
        self.folder: str | None = None
        self.current_file: str | None = None
        self.last_file: str | None = None  # remembered after "Clear" so "Reload" still works
        self.key = None
        self.key_path: str | None = None
        self.analysis: cc.Analysis | None = None
        self.chain_items: dict[str, cc.CertInfo] = {}
        self.use_folder = tk.BooleanVar(value=True)
        self.recursive = tk.BooleanVar(value=True)
        self._build()

    def _build(self):
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=24, pady=(18, 6))
        RoundButton(bar, "Choose Folder…", self.browse_folder, "primary").pack(side="left")
        RoundButton(bar, "Open File…", self.open_file).pack(side="left", padx=(8, 0))
        RoundButton(bar, "Private Key…", self.choose_key).pack(side="left", padx=(8, 0))
        tk.Frame(bar, bg=BORDER, width=1, height=22).pack(side="left", padx=14)
        RoundButton(bar, "↻  Reload File", self.reload_file).pack(side="left")
        RoundButton(bar, "✕  Clear Results", self.clear_results).pack(side="left", padx=(8, 0))
        RoundButton(bar, "Export Report…", self.export_report).pack(side="right")
        RoundButton(bar, "Copy Report", self.copy_report).pack(side="right", padx=8)

        opts = tk.Frame(self, bg=BG)
        opts.pack(fill="x", padx=24, pady=(4, 8))
        checkbox(opts, "Use other certificates in the same folder to complete the chain",
                 self.use_folder, self.reanalyze).pack(side="left")
        checkbox(opts, "Include sub-folders", self.recursive, self.refresh_folder).pack(side="left", padx=(20, 0))
        self.key_box = tk.Frame(opts, bg=BG)
        self.key_box.pack(side="right")
        self.key_label = tk.Label(self.key_box, text="", font=F["body"], bg=BG, fg=MUTED)
        self.key_label.pack(side="left")
        self.key_remove = tk.Label(self.key_box, text="Remove", font=F["body"], bg=BG, fg=ACCENT, cursor="hand2")
        self.key_remove.bind("<Button-1>", lambda e: self.clear_key())

        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        # Sidebar: files
        left, _, body = card(paned, "Files")
        self.folder_label = tk.Label(left, text="Choose a folder to list its certificate files.",
                                     font=F["small"], bg=CARD, fg=MUTED, anchor="w", justify="left", wraplength=320)
        self.folder_label.pack(before=body, fill="x", padx=16, pady=(0, 6))
        self.files = scrolled_tree(body, columns=("summary",), show="tree headings", selectmode="browse")
        self.files.heading("#0", text="NAME", anchor="w")
        self.files.heading("summary", text="CONTENTS", anchor="w")
        self.files.column("#0", width=170, minwidth=120)
        self.files.column("summary", width=210, minwidth=120)
        self.files.bind("<<TreeviewSelect>>", self._on_file_select)
        paned.add(left, weight=1)

        right = tk.Frame(paned, bg=BG)
        paned.add(right, weight=3)

        # Status banner
        banner = tk.Frame(right, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        banner.pack(fill="x", pady=(0, 12))
        self.banner_bar = tk.Frame(banner, bg=BORDER, width=6)
        self.banner_bar.pack(side="left", fill="y")
        inner = tk.Frame(banner, bg=CARD)
        inner.pack(side="left", fill="both", expand=True, padx=16, pady=6)
        self.banner_title = tk.Label(inner, text="No certificate selected", font=F["banner"], bg=CARD, fg=TEXT, anchor="w")
        self.banner_title.pack(fill="x")
        self.banner_sub = tk.Label(inner, text="Choose a folder or open a certificate file to validate it.",
                                   font=F["body"], bg=CARD, fg=MUTED, anchor="w")
        self.banner_sub.pack(fill="x")

        rpaned = ttk.PanedWindow(right, orient="vertical")
        rpaned.pack(fill="both", expand=True)

        chain_card, _, body = card(rpaned, "Certificate Chain")
        cols = ("role", "valid_to", "days", "where")
        self.chain = scrolled_tree(body, columns=cols, show="tree headings", height=4, selectmode="browse")
        self.chain.heading("#0", text="SUBJECT CN", anchor="w")
        self.chain.column("#0", width=300, minwidth=160)
        for c, t, w in [("role", "ROLE", 110), ("valid_to", "VALID UNTIL", 200), ("days", "DAYS LEFT", 90),
                        ("where", "FOUND IN", 160)]:
            self.chain.heading(c, text=t, anchor="w")
            self.chain.column(c, width=w, minwidth=60, anchor="w")
        self.chain.bind("<<TreeviewSelect>>", self._on_chain_select)
        rpaned.add(chain_card, weight=2)

        checks_card, _, body = card(rpaned, "Checks")
        self.findings = scrolled_tree(body, columns=("msg",), show="tree", height=6, selectmode="none")
        self.findings.column("#0", width=120, stretch=False)
        self.findings.column("msg", width=700)
        rpaned.add(checks_card, weight=2)

        det_card, hdr, body = card(rpaned, "Details")
        tk.Label(hdr, text="Select a certificate in the chain", font=F["small"], bg=CARD, fg=MUTED).pack(side="left", padx=10)
        self.details = tk.Text(body, height=10, wrap="none", font=F["mono"], bg=CARD, fg=TEXT, relief="flat",
                               bd=0, highlightthickness=0, padx=8, pady=4, selectbackground=SELECTED)
        dsb = ttk.Scrollbar(body, orient="vertical", command=self.details.yview, style="Mac.Vertical.TScrollbar")
        self.details.configure(yscrollcommand=autohide(dsb), state="disabled")
        self.details.pack(side="left", fill="both", expand=True)
        rpaned.add(det_card, weight=3)

    # ---- banner --------------------------------------------------------
    def _banner(self, sev: str | None, title: str, sub: str):
        color = SEV_FG.get(sev, BORDER) if sev else BORDER
        self.banner_bar.configure(bg=color)
        self.banner_title.configure(text=title, fg=SEV_FG.get(sev, TEXT) if sev else TEXT)
        self.banner_sub.configure(text=sub)

    # ---- folder / file -------------------------------------------------
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Choose a folder with certificates", parent=self)
        if folder:
            self.folder = folder
            self.refresh_folder()

    def refresh_folder(self):
        if not self.folder:
            return
        self.files.delete(*self.files.get_children())
        parts = os.path.normpath(self.folder).split(os.sep)
        short = os.sep.join(parts[-2:]) if len(parts) > 2 else self.folder
        self.folder_label.configure(text=("…" + os.sep if len(parts) > 2 else "") + short)
        files = cc.scan_folder(self.folder, recursive=self.recursive.get())
        if not files:
            self.files.insert("", "end", text="No certificate files found", tags=("muted",))
            return
        for p in files:
            summary, sev = self._quick_summary(p)
            tags = ("fg_" + sev,) if sev else ()
            self.files.insert("", "end", iid=p, text=os.path.relpath(p, self.folder), values=(summary,), tags=tags)

    def _quick_summary(self, path: str) -> tuple[str, str]:
        try:
            certs = cc.load_certificates(path, self.pw.passwords.get(path))
        except cc.PasswordRequired:
            return "Password protected", ""
        except cc.CertLoadError as e:
            msg = str(e)
            if "private key" in msg:
                return "Private key", ""
            if "CSR" in msg:
                return "Certificate request (CSR)", ""
            return "Not a certificate", ""
        except Exception:
            return "Unreadable", ""
        roles = [c.role for c in certs]
        parts = [f"{roles.count(r)} {r.lower()}" for r in ("Leaf", "Intermediate", "Root", "Self-signed") if roles.count(r)]
        leaf = cc.pick_leaf(certs)
        sev, _ = leaf.validity_status()
        return f"{leaf.display_name} · {', '.join(parts)}", sev if sev != cc.OK else ""

    def open_file(self):
        path = filedialog.askopenfilename(title="Open certificate", filetypes=FILE_TYPES, parent=self)
        if not path:
            return
        folder = os.path.dirname(path)
        if folder != self.folder:
            self.folder = folder
            self.refresh_folder()
        if self.files.exists(path):
            self.files.selection_set(path)
            self.files.see(path)
        else:
            self.analyze_file(path)

    # ---- private key ---------------------------------------------------
    def choose_key(self):
        path = filedialog.askopenfilename(title="Open private key", filetypes=KEY_TYPES, parent=self)
        if not path:
            return
        try:
            self.key = self.pw.load_key(path)
        except cc.PasswordRequired:
            return
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Could not load private key:\n{e}", parent=self)
            return
        self.key_path = path
        self.key_label.configure(text=f"Private key: {os.path.basename(path)}  ")
        self.key_remove.pack(side="left")
        self.reanalyze()

    def clear_key(self):
        self.key = None
        self.key_path = None
        self.key_label.configure(text="")
        self.key_remove.pack_forget()
        self.reanalyze()

    # ---- analysis ------------------------------------------------------
    def _on_file_select(self, _evt=None):
        sel = self.files.selection()
        if sel and os.path.isfile(sel[0]) and not (sel[0] == self.current_file and self.analysis):
            self.analyze_file(sel[0])

    def clear_results(self):
        """Clear the results; the file is remembered so Reload can check it again."""
        self.last_file = self.current_file or self.last_file
        self.current_file = None
        self.analysis = None
        self._clear()
        self._set_details("")
        self.files.selection_remove(*self.files.selection())
        self._banner(None, "No certificate selected",
                     "Results cleared. Click Reload File to check "
                     f"{os.path.basename(self.last_file)} again." if self.last_file
                     else "Choose a folder or open a certificate file to validate it.")

    def reload_file(self):
        """Read the last file again from disk (e.g. after it was replaced) and re-run all checks."""
        path = self.current_file or self.last_file
        if not path:
            messagebox.showinfo(APP_TITLE, "Open a certificate file first.", parent=self)
            return
        if not os.path.isfile(path):
            messagebox.showerror(APP_TITLE, f"File no longer exists:\n{path}", parent=self)
            return
        self.pw.passwords.pop(path, None)  # file may have changed: ask again if needed
        self.refresh_folder()  # pick up new / renamed files in the folder too
        self.analyze_file(path)
        if self.files.exists(path):
            self.files.selection_set(path)
            self.files.see(path)

    def reanalyze(self):
        if self.current_file:
            self.analyze_file(self.current_file)

    def analyze_file(self, path: str):
        self.current_file = self.last_file = path
        try:
            certs = self.pw.load_certs(path)
        except cc.PasswordRequired:
            self._show_error(path, "A password is required to open this file.")
            return
        except Exception as e:
            self._show_error(path, str(e))
            return
        pool = cc.load_folder_certs(os.path.dirname(path), exclude=path) if self.use_folder.get() else []
        key = self.key
        if key is None and os.path.splitext(path.lower())[1] in (".pfx", ".p12"):
            key = cc.load_pkcs12_key(path, self.pw.passwords.get(path))
        try:
            self.analysis = cc.analyze(certs, extra_pool=pool, private_key=key)
        except Exception as e:  # pragma: no cover - defensive
            self._show_error(path, f"Analysis failed: {e}")
            return
        self._render(path)

    def _clear(self):
        self.chain.delete(*self.chain.get_children())
        self.findings.delete(*self.findings.get_children())
        self.chain_items.clear()

    def _show_error(self, path, msg):
        self.analysis = None
        self._clear()
        self._banner(cc.ERROR, "✕  Cannot read this file", f"{os.path.basename(path)} — {msg}")
        self._add_finding(cc.Finding(cc.ERROR, msg))
        self._set_details("")

    def _render(self, path: str):
        a = self.analysis
        assert a is not None
        self._clear()

        worst = a.worst
        complete = all(c.complete for c in a.chains)
        title = {cc.ERROR: "✕  Problems found", cc.WARN: "!  Valid, with warnings",
                 cc.OK: "✓  Valid certificate chain", cc.INFO: "✓  Valid certificate chain"}[worst]
        n_err = sum(1 for f in a.findings + [f for c in a.chains for f in c.findings] if f.severity == cc.ERROR)
        n_warn = sum(1 for f in a.findings + [f for c in a.chains for f in c.findings] if f.severity == cc.WARN)
        sub = (f"{os.path.basename(path)}   ·   chain {'complete' if complete else 'incomplete'}"
               f"   ·   {n_err} error(s), {n_warn} warning(s)")
        self._banner(cc.OK if worst == cc.INFO else worst, title, sub)

        file_fps = {c.fingerprint_sha256 for c in a.file_certs}
        first_leaf = None
        for n, ch in enumerate(a.chains):
            parent = ""
            if not ch.complete:
                parent = self.chain.insert("", "end", text=f"Missing: {ch.missing_issuer_cn or ch.missing_issuer}", open=True, tags=(cc.ERROR,),
                                           values=("Missing", "", "", "not provided"))
            for ci in reversed(ch.chain):
                sev, _ = ci.validity_status()
                where = "This file" if ci.fingerprint_sha256 in file_fps else os.path.basename(ci.source)
                tags = ("fg_" + sev,) if sev != cc.OK else ()
                iid = self.chain.insert(parent, "end", text=ci.display_name, open=True, tags=tags,
                                        values=(ci.role, cc.fmt_date(ci.not_after), ci.days_remaining(), where))
                self.chain_items[iid] = ci
                parent = iid
            first_leaf = first_leaf or parent
            if len(a.chains) > 1:
                self.findings.insert("", "end", text=f"Chain {n + 1}", values=(ch.chain[0].display_name,), tags=("bold",))
            for f in ch.findings:
                self._add_finding(f)
        for f in a.findings:
            self._add_finding(f)

        if first_leaf:
            self.chain.selection_set(first_leaf)
            self.chain.see(first_leaf)

    def _add_finding(self, f: cc.Finding):
        self.findings.insert("", "end", text=f"  {SEV_ICON[f.severity]}   {SEV_LABEL[f.severity]}",
                             values=(f.message,), tags=(f.severity,))

    def _on_chain_select(self, _evt=None):
        sel = self.chain.selection()
        ci = self.chain_items.get(sel[0]) if sel else None
        self._set_details(ci.details_text() if ci else "")

    def _set_details(self, text: str):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    # ---- report --------------------------------------------------------
    def _report(self) -> str | None:
        if not self.analysis:
            messagebox.showinfo(APP_TITLE, "Validate a certificate first.", parent=self)
            return None
        return f"File: {self.current_file}\n" + self.analysis.report_text()

    def copy_report(self):
        r = self._report()
        if r:
            self.clipboard_clear()
            self.clipboard_append(r)

    def export_report(self):
        r = self._report()
        if not r:
            return
        path = filedialog.asksaveasfilename(
            title="Save report", defaultextension=".txt",
            initialfile=os.path.splitext(os.path.basename(self.current_file or "report"))[0] + "_report.txt",
            filetypes=[("Text", "*.txt")], parent=self,
        )
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(r)


# ---------------------------------------------------------------------------
# Compare page
# ---------------------------------------------------------------------------

class CertSlot(tk.Frame):
    """Card showing one chosen certificate (current or new)."""

    def __init__(self, master, title: str, pw: PasswordCache, on_change):
        super().__init__(master, bg=BG)
        self.pw, self.on_change = pw, on_change
        self.certs: list[cc.CertInfo] = []
        self.path = ""
        outer, hdr, body = card(self, title)
        outer.pack(fill="both", expand=True)
        RoundButton(hdr, "Choose…", self.browse).pack(side="right")
        self.cn = tk.Label(body, text="No certificate selected", font=F["cn"], bg=CARD, fg=MUTED, anchor="w")
        self.cn.pack(fill="x", padx=6)
        self.issuer = tk.Label(body, text=" ", font=F["body"], bg=CARD, fg=MUTED, anchor="w")
        self.issuer.pack(fill="x", padx=6)
        self.valid = tk.Label(body, text=" ", font=F["body_bold"], bg=CARD, fg=TEXT, anchor="w")
        self.valid.pack(fill="x", padx=6, pady=(2, 0))
        self.file = tk.Label(body, text=" ", font=F["small"], bg=CARD, fg=MUTED, anchor="w")
        self.file.pack(fill="x", padx=6, pady=(2, 4))
        self.choice = ttk.Combobox(body, state="readonly", style="Mac.TCombobox")
        self.choice.bind("<<ComboboxSelected>>", lambda e: self._changed())

    def browse(self):
        path = filedialog.askopenfilename(title="Open certificate", filetypes=FILE_TYPES, parent=self)
        if not path:
            return
        try:
            certs = self.pw.load_certs(path)
        except cc.PasswordRequired:
            return
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Could not read {os.path.basename(path)}:\n{e}", parent=self)
            return
        self.set_state(certs, path, certs.index(cc.pick_leaf(certs)))

    def get_state(self):
        return self.certs, self.path, self.choice.current() if self.certs else -1

    def set_state(self, certs, path, index):
        self.certs, self.path = certs, path
        if certs:
            self.choice["values"] = [f"{i + 1}.  {c.role} — {c.display_name}" for i, c in enumerate(certs)]
            self.choice.current(max(index, 0))
            if len(certs) > 1:
                self.choice.pack(fill="x", padx=6, pady=(4, 0))
            else:
                self.choice.pack_forget()
        else:
            self.choice["values"] = []
            self.choice.set("")
            self.choice.pack_forget()
        self._changed()

    def _changed(self):
        c = self.selected
        if c is None:
            self.cn.configure(text="No certificate selected", fg=MUTED)
            for w in (self.issuer, self.valid, self.file):
                w.configure(text=" ")
        else:
            sev, msg = c.validity_status()
            self.cn.configure(text=c.display_name, fg=TEXT)
            self.issuer.configure(text=f"Issued by {c.issuer_cn or c.issuer}")
            self.valid.configure(text=f"{SEV_ICON[sev]}  {msg}", fg=SEV_FG[sev])
            self.file.configure(text=self.path)
        self.on_change()

    @property
    def selected(self) -> cc.CertInfo | None:
        if not self.certs:
            return None
        i = self.choice.current()
        return self.certs[i if i >= 0 else 0]


class ComparePage(tk.Frame):
    def __init__(self, master, pw: PasswordCache):
        super().__init__(master, bg=BG)
        self.rows: list[cc.CompareRow] = []
        self.only_diff = tk.BooleanVar(value=False)

        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=24, pady=(18, 0))
        top.columnconfigure(0, weight=1, uniform="slot")
        top.columnconfigure(2, weight=1, uniform="slot")
        self.old = CertSlot(top, "Current Certificate", pw, self.compare)
        self.old.grid(row=0, column=0, sticky="nsew")
        tk.Label(top, text="→", font=F["banner"], bg=BG, fg=MUTED).grid(row=0, column=1, padx=12)
        self.new = CertSlot(top, "New Certificate", pw, self.compare)
        self.new.grid(row=0, column=2, sticky="nsew")

        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=24, pady=10)
        checkbox(bar, "Show only differences", self.only_diff, self._fill_table).pack(side="left")
        RoundButton(bar, "⇄  Swap", self.swap).pack(side="left", padx=(16, 8))
        RoundButton(bar, "✕  Clear", self.clear).pack(side="left")
        tk.Label(bar, text="Highlighted rows differ · double-click a row to see full values",
                 font=F["small"], bg=BG, fg=MUTED).pack(side="right")

        pane = ttk.PanedWindow(self, orient="vertical")
        pane.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        sum_card, _, body = card(pane, "Summary")
        self.summary = scrolled_tree(body, columns=("msg",), show="tree", height=6, selectmode="none")
        self.summary.column("#0", width=120, stretch=False)
        self.summary.column("msg", width=800)
        pane.add(sum_card, weight=1)

        tbl_card, _, body = card(pane, "Side-by-side Comparison")
        self.table = scrolled_tree(body, columns=("field", "old", "new"), show="headings")
        for c, t, w in [("field", "FIELD", 170), ("old", "CURRENT", 420), ("new", "NEW", 420)]:
            self.table.heading(c, text=t, anchor="w")
            self.table.column(c, width=w, minwidth=80, anchor="w")
        self.table.bind("<Double-1>", self._show_row)
        pane.add(tbl_card, weight=3)

    def clear(self):
        self.old.set_state([], "", -1)
        self.new.set_state([], "", -1)

    def swap(self):
        a, b = self.old.get_state(), self.new.get_state()
        self.old.set_state(*b)
        self.new.set_state(*a)

    def compare(self):
        if not hasattr(self, "summary"):
            return  # still building
        self.summary.delete(*self.summary.get_children())
        a, b = self.old.selected, self.new.selected
        if a is None or b is None:
            single = a or b
            self.rows = []
            if single:
                self.rows = [cc.CompareRow(r.field, r.old if a else "", r.new if b else "")
                             for r in cc.compare(single, single)[0]]
                self.summary.insert("", "end", text="", values=("Choose the other certificate to compare.",),
                                    tags=("muted",))
            self._fill_table()
            return
        self.rows, findings = cc.compare(a, b)
        for f in findings:
            self.summary.insert("", "end", text=f"  {SEV_ICON[f.severity]}   {SEV_LABEL[f.severity]}",
                                values=(f.message,), tags=(f.severity,))
        self._fill_table()

    def _fill_table(self):
        self.table.delete(*self.table.get_children())
        both = self.old.selected is not None and self.new.selected is not None
        for i, r in enumerate(self.rows):
            diff = both and not r.same and r.field != "Source file"
            if self.only_diff.get() and both and not diff:
                continue
            self.table.insert("", "end", iid=str(i),
                              values=(r.field, r.old.replace("\n", ", "), r.new.replace("\n", ", ")),
                              tags=("diff",) if diff else ())

    def _show_row(self, _evt=None):
        sel = self.table.selection()
        if not sel:
            return
        r = self.rows[int(sel[0])]
        win = tk.Toplevel(self, bg=BG)
        win.title(r.field)
        win.geometry("940x420")
        for col, (title, val) in enumerate((("Current", r.old), ("New", r.new))):
            outer, _, body = card(win, title)
            outer.grid(row=0, column=col, sticky="nsew", padx=(16 if col == 0 else 8, 16 if col else 8), pady=16)
            t = tk.Text(body, wrap="word", font=F["mono"], bg=CARD, fg=TEXT, relief="flat", bd=0,
                        highlightthickness=0, padx=6)
            t.insert("1.0", val)
            t.configure(state="disabled")
            t.pack(fill="both", expand=True)
        win.columnconfigure(0, weight=1)
        win.columnconfigure(1, weight=1)
        win.rowconfigure(0, weight=1)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1360x900")
        self.minsize(1000, 680)
        init_style(self)
        pw = PasswordCache(self)

        # Header: wide, clean title bar
        header = tk.Frame(self, bg=CARD)
        header.pack(fill="x")
        inner = tk.Frame(header, bg=CARD)
        inner.pack(fill="x", padx=28, pady=9)

        icon = tk.Canvas(inner, width=40, height=40, bg=CARD, highlightthickness=0)
        round_rect(icon, 1, 1, 39, 39, 10, fill=ACCENT, outline="")
        # simple padlock glyph
        icon.create_arc(13, 8, 27, 23, start=0, extent=180, style="arc", outline="#ffffff", width=3)
        icon.create_line(13, 15, 13, 19, fill="#ffffff", width=3)
        icon.create_line(27, 15, 27, 19, fill="#ffffff", width=3)
        round_rect(icon, 9, 18, 31, 33, 4, fill="#ffffff", outline="")
        icon.create_oval(18, 23, 22, 27, fill=ACCENT, outline="")
        icon.pack(side="left")

        titles = tk.Frame(inner, bg=CARD)
        titles.pack(side="left", padx=14)
        tk.Label(titles, text=APP_TITLE, font=F["title"], bg=CARD, fg=TEXT, anchor="w").pack(fill="x")
        tk.Label(titles, text="Check certificate chains and compare renewals", font=F["subtitle"],
                 bg=CARD, fg=MUTED, anchor="w").pack(fill="x")

        self.pages = tk.Frame(self, bg=BG)
        self.validate_page = ValidatePage(self.pages, pw)
        self.compare_page = ComparePage(self.pages, pw)
        self.segmented = Segmented(inner, ["Validate", "Compare"], self._show_page, height=30)
        self.segmented.pack(side="right")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        self.pages.pack(fill="both", expand=True)
        self._show_page(0)

    def _show_page(self, i: int):
        for p in (self.validate_page, self.compare_page):
            p.pack_forget()
        (self.validate_page if i == 0 else self.compare_page).pack(fill="both", expand=True)


def _enable_dpi_awareness():
    """Crisp (non-blurry) text on high-DPI Windows displays."""
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass


def main():
    _enable_dpi_awareness()
    App().mainloop()


if __name__ == "__main__":
    main()
