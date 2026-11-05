"""Tkinter user interface for the SSL certificate validator."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import certcore as cc

APP_TITLE = "SSL Certificate Validator"

FILE_TYPES = [
    ("Certificate files", "*.pem *.crt *.cer *.cert *.der *.p7b *.p7c *.pfx *.p12 *.ca-bundle *.bundle *.chain"),
    ("All files", "*.*"),
]
KEY_TYPES = [("Private keys", "*.key *.pem *.pfx *.p12"), ("All files", "*.*")]

SEV_COLORS = {
    cc.ERROR: "#f8d7da",
    cc.WARN: "#fff3cd",
    cc.OK: "#d4edda",
    cc.INFO: "#e7f1ff",
}
SEV_ICON = {cc.ERROR: "✖", cc.WARN: "⚠", cc.OK: "✔", cc.INFO: "ℹ"}
DIFF_COLOR = "#ffe8b3"


def _tag_colors(tree: ttk.Treeview) -> None:
    for sev, color in SEV_COLORS.items():
        tree.tag_configure(sev, background=color)
    tree.tag_configure("diff", background=DIFF_COLOR)
    tree.tag_configure("same", background="")


class PasswordCache:
    """Asks for PKCS#12 / encrypted key passwords once per file."""

    def __init__(self, root: tk.Misc):
        self.root = root
        self.passwords: dict[str, str] = {}

    def load_certs(self, path: str, interactive: bool = True) -> list[cc.CertInfo]:
        pw = self.passwords.get(path)
        while True:
            try:
                certs = cc.load_certificates(path, pw)
                if pw is not None:
                    self.passwords[path] = pw
                return certs
            except cc.PasswordRequired:
                if not interactive:
                    raise
                prompt = "Password for" if pw is None else "Wrong password. Password for"
                pw = simpledialog.askstring(APP_TITLE, f"{prompt}\n{os.path.basename(path)}:", show="*", parent=self.root)
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
                prompt = "Password for" if pw is None else "Wrong password. Password for"
                pw = simpledialog.askstring(APP_TITLE, f"{prompt}\n{os.path.basename(path)}:", show="*", parent=self.root)
                if pw is None:
                    raise


# ---------------------------------------------------------------------------
# Validate tab
# ---------------------------------------------------------------------------

class ValidateTab(ttk.Frame):
    def __init__(self, master, pw: PasswordCache):
        super().__init__(master, padding=6)
        self.pw = pw
        self.folder: str | None = None
        self.current_file: str | None = None
        self.key_path: str | None = None
        self.key = None
        self.analysis: cc.Analysis | None = None
        self.chain_items: dict[str, cc.CertInfo] = {}

        self.use_folder = tk.BooleanVar(value=True)
        self.use_store = tk.BooleanVar(value=True)
        self.recursive = tk.BooleanVar(value=True)

        self._build()

    # ---- layout --------------------------------------------------------
    def _build(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x")
        ttk.Button(bar, text="📁 Browse folder…", command=self.browse_folder).pack(side="left")
        ttk.Button(bar, text="📄 Open certificate file…", command=self.open_file).pack(side="left", padx=4)
        ttk.Button(bar, text="🔑 Private key…", command=self.choose_key).pack(side="left")
        ttk.Button(bar, text="Clear key", command=self.clear_key).pack(side="left", padx=4)
        ttk.Button(bar, text="Export report…", command=self.export_report).pack(side="right")
        ttk.Button(bar, text="Copy report", command=self.copy_report).pack(side="right", padx=4)

        opts = ttk.Frame(self)
        opts.pack(fill="x", pady=(4, 2))
        ttk.Checkbutton(opts, text="Use other certificates in the same folder to complete the chain",
                        variable=self.use_folder, command=self.reanalyze).pack(side="left")
        ttk.Checkbutton(opts, text="Look up missing root in system trust store",
                        variable=self.use_store, command=self.reanalyze).pack(side="left", padx=10)
        ttk.Checkbutton(opts, text="Include sub-folders", variable=self.recursive,
                        command=self.refresh_folder).pack(side="left")

        self.key_label = ttk.Label(self, text="Private key: (none)", foreground="#555")
        self.key_label.pack(fill="x")

        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, pady=4)

        # Left: files in folder
        left = ttk.Frame(main)
        self.folder_label = ttk.Label(left, text="No folder selected", font=("TkDefaultFont", 9, "bold"))
        self.folder_label.pack(fill="x")
        self.files = ttk.Treeview(left, columns=("summary",), show="tree headings", selectmode="browse")
        self.files.heading("#0", text="File")
        self.files.heading("summary", text="Contents")
        self.files.column("#0", width=200)
        self.files.column("summary", width=220)
        _tag_colors(self.files)
        fsb = ttk.Scrollbar(left, orient="vertical", command=self.files.yview)
        self.files.configure(yscrollcommand=fsb.set)
        self.files.pack(side="left", fill="both", expand=True)
        fsb.pack(side="left", fill="y")
        self.files.bind("<<TreeviewSelect>>", self._on_file_select)
        main.add(left, weight=1)

        # Right: chain / findings / details
        right = ttk.PanedWindow(main, orient="vertical")
        main.add(right, weight=3)

        chain_frame = ttk.LabelFrame(right, text="Certificate chain (Root → Intermediate → Leaf)", padding=4)
        self.result_label = ttk.Label(chain_frame, text="Select a certificate file", font=("TkDefaultFont", 11, "bold"))
        self.result_label.pack(fill="x")
        cols = ("role", "cn", "valid_to", "days", "where")
        self.chain = ttk.Treeview(chain_frame, columns=cols, show="tree headings", height=6, selectmode="browse")
        self.chain.heading("#0", text="Chain")
        for c, t, w in [("role", "Role", 90), ("cn", "Subject CN", 220), ("valid_to", "Valid to", 150),
                        ("days", "Days left", 70), ("where", "Found in", 160)]:
            self.chain.heading(c, text=t)
            self.chain.column(c, width=w, anchor="w")
        self.chain.column("#0", width=260)
        _tag_colors(self.chain)
        self.chain.pack(fill="both", expand=True)
        self.chain.bind("<<TreeviewSelect>>", self._on_chain_select)
        right.add(chain_frame, weight=2)

        find_frame = ttk.LabelFrame(right, text="Checks", padding=4)
        self.findings = ttk.Treeview(find_frame, columns=("msg",), show="tree", height=8)
        self.findings.column("#0", width=110, stretch=False)
        self.findings.column("msg", width=700)
        _tag_colors(self.findings)
        ffsb = ttk.Scrollbar(find_frame, orient="vertical", command=self.findings.yview)
        self.findings.configure(yscrollcommand=ffsb.set)
        self.findings.pack(side="left", fill="both", expand=True)
        ffsb.pack(side="left", fill="y")
        right.add(find_frame, weight=2)

        det_frame = ttk.LabelFrame(right, text="Certificate details (select a certificate in the chain)", padding=4)
        self.details = tk.Text(det_frame, height=12, wrap="none", font=("Courier New", 9))
        dsb = ttk.Scrollbar(det_frame, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=dsb.set, state="disabled")
        self.details.pack(side="left", fill="both", expand=True)
        dsb.pack(side="left", fill="y")
        right.add(det_frame, weight=3)

    # ---- actions -------------------------------------------------------
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Choose a folder with certificates", parent=self)
        if folder:
            self.folder = folder
            self.refresh_folder()

    def refresh_folder(self):
        if not self.folder:
            return
        self.files.delete(*self.files.get_children())
        self.folder_label.configure(text=self.folder)
        files = cc.scan_folder(self.folder, recursive=self.recursive.get())
        if not files:
            self.files.insert("", "end", text="(no certificate files found)")
            return
        for p in files:
            summary, sev = self._quick_summary(p)
            rel = os.path.relpath(p, self.folder)
            self.files.insert("", "end", iid=p, text=rel, values=(summary,), tags=(sev,) if sev else ())

    def _quick_summary(self, path: str) -> tuple[str, str]:
        try:
            certs = cc.load_certificates(path, self.pw.passwords.get(path))
        except cc.PasswordRequired:
            return "🔒 password protected", ""
        except cc.CertLoadError as e:
            msg = str(e)
            if "private key" in msg:
                return "🔑 private key", ""
            if "CSR" in msg:
                return "CSR (request)", ""
            return "not a certificate", ""
        except Exception:
            return "unreadable", ""
        roles = [c.role for c in certs]
        parts = []
        for r in ("Leaf", "Intermediate", "Root", "Self-signed"):
            n = roles.count(r)
            if n:
                parts.append(f"{n} {r.lower()}")
        leaf = cc.pick_leaf(certs)
        sev, _ = leaf.validity_status()
        return f"{leaf.display_name} — {', '.join(parts)}", sev if sev != cc.OK else ""

    def open_file(self):
        path = filedialog.askopenfilename(title="Open certificate", filetypes=FILE_TYPES, parent=self)
        if path:
            folder = os.path.dirname(path)
            if folder != self.folder:
                self.folder = folder
                self.refresh_folder()
            if self.files.exists(path):
                self.files.selection_set(path)
                self.files.see(path)
            else:
                self.analyze_file(path)

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
        self.key_label.configure(text=f"Private key: {path}")
        self.reanalyze()

    def clear_key(self):
        self.key = None
        self.key_path = None
        self.key_label.configure(text="Private key: (none)")
        self.reanalyze()

    def _on_file_select(self, _evt=None):
        sel = self.files.selection()
        if sel and os.path.isfile(sel[0]):
            self.analyze_file(sel[0])

    def reanalyze(self):
        if self.current_file:
            self.analyze_file(self.current_file)

    def analyze_file(self, path: str):
        self.current_file = path
        try:
            certs = self.pw.load_certs(path)
        except cc.PasswordRequired:
            self._show_error(path, "Password required (PKCS#12 file) — cancelled.")
            return
        except Exception as e:
            self._show_error(path, str(e))
            return
        pool = []
        if self.use_folder.get():
            pool = cc.load_folder_certs(os.path.dirname(path), exclude=path)
        key = self.key
        if key is None and os.path.splitext(path.lower())[1] in (".pfx", ".p12"):
            key = cc.load_pkcs12_key(path, self.pw.passwords.get(path))
        try:
            self.analysis = cc.analyze(certs, extra_pool=pool, use_trust_store=self.use_store.get(), private_key=key)
        except Exception as e:  # pragma: no cover - defensive
            self._show_error(path, f"Analysis failed: {e}")
            return
        self._render(path)

    def _show_error(self, path, msg):
        self.analysis = None
        self.chain.delete(*self.chain.get_children())
        self.findings.delete(*self.findings.get_children())
        self.result_label.configure(text=f"{os.path.basename(path)}: cannot read", foreground="#a00")
        self.findings.insert("", "end", text=f"{SEV_ICON[cc.ERROR]} {cc.ERROR}", values=(msg,), tags=(cc.ERROR,))
        self._set_details("")

    def _render(self, path: str):
        a = self.analysis
        assert a is not None
        self.chain.delete(*self.chain.get_children())
        self.findings.delete(*self.findings.get_children())
        self.chain_items.clear()

        worst = a.worst
        complete = all(c.complete for c in a.chains)
        txt = {cc.ERROR: "PROBLEMS FOUND", cc.WARN: "VALID WITH WARNINGS", cc.OK: "VALID", cc.INFO: "VALID"}[worst]
        color = {cc.ERROR: "#a00", cc.WARN: "#a60", cc.OK: "#070", cc.INFO: "#070"}[worst]
        self.result_label.configure(
            text=f"{'✔' if worst == cc.INFO else SEV_ICON[worst]} {os.path.basename(path)} — {txt} — chain {'complete' if complete else 'INCOMPLETE'}",
            foreground=color,
        )

        file_fps = {c.fingerprint_sha256 for c in a.file_certs}
        first_leaf_iid = None
        for n, ch in enumerate(a.chains):
            parent = ""
            if not ch.complete:
                parent = self.chain.insert(
                    "", "end", text="❓ MISSING issuer", open=True, tags=(cc.ERROR,),
                    values=("missing", ch.missing_issuer, "", "", "not found"),
                )
            for ci in reversed(ch.chain):
                sev, _ = ci.validity_status()
                if ci.fingerprint_sha256 in file_fps:
                    where = "this file"
                elif ci.source == cc.TRUST_STORE:
                    where = "system trust store"
                else:
                    where = os.path.basename(ci.source)
                tags = (sev,) if sev != cc.OK else (() if where == "this file" else (cc.INFO,))
                iid = self.chain.insert(
                    parent, "end", text=f"{SEV_ICON.get(sev, '')} {ci.display_name}", open=True, tags=tags,
                    values=(ci.role, ci.subject_cn, cc.fmt_date(ci.not_after), ci.days_remaining(), where),
                )
                self.chain_items[iid] = ci
                parent = iid
            first_leaf_iid = first_leaf_iid or parent

            if len(a.chains) > 1:
                self.findings.insert("", "end", text=f"Chain #{n + 1}", values=(ch.chain[0].display_name,))
            for f in ch.findings:
                self._add_finding(f)
        for f in a.findings:
            self._add_finding(f)

        if first_leaf_iid:
            self.chain.selection_set(first_leaf_iid)
            self.chain.see(first_leaf_iid)

    def _add_finding(self, f: cc.Finding):
        self.findings.insert("", "end", text=f"{SEV_ICON[f.severity]} {f.severity}", values=(f.message,), tags=(f.severity,))

    def _on_chain_select(self, _evt=None):
        sel = self.chain.selection()
        ci = self.chain_items.get(sel[0]) if sel else None
        self._set_details(ci.details_text() if ci else "")

    def _set_details(self, text: str):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _report(self) -> str | None:
        if not self.analysis:
            messagebox.showinfo(APP_TITLE, "Analyse a certificate first.", parent=self)
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
# Compare tab
# ---------------------------------------------------------------------------

class CertPicker(ttk.Frame):
    """Row with label, path entry, Browse button and a selector for which cert in the file."""

    def __init__(self, master, label: str, pw: PasswordCache, on_change):
        super().__init__(master)
        self.pw = pw
        self.on_change = on_change
        self.certs: list[cc.CertInfo] = []
        self.path = tk.StringVar()
        ttk.Label(self, text=label, width=20, font=("TkDefaultFont", 9, "bold")).pack(side="left")
        ttk.Entry(self, textvariable=self.path, state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(self, text="Browse…", command=self.browse).pack(side="left", padx=4)
        self.choice = ttk.Combobox(self, state="readonly", width=45)
        self.choice.pack(side="left")
        self.choice.bind("<<ComboboxSelected>>", lambda e: self.on_change())

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
        self.path.set(path)
        self.certs = certs
        self.choice["values"] = [f"#{i + 1} [{c.role}] {c.display_name}" for i, c in enumerate(certs)]
        leaf = cc.pick_leaf(certs)
        self.choice.current(certs.index(leaf))
        self.on_change()

    @property
    def selected(self) -> cc.CertInfo | None:
        if not self.certs:
            return None
        i = self.choice.current()
        return self.certs[i if i >= 0 else 0]


class CompareTab(ttk.Frame):
    def __init__(self, master, pw: PasswordCache):
        super().__init__(master, padding=6)
        self.pw = pw
        self.rows: list[cc.CompareRow] = []
        self.only_diff = tk.BooleanVar(value=False)

        self.old = CertPicker(self, "Current certificate:", pw, self.compare)
        self.old.pack(fill="x", pady=2)
        self.new = CertPicker(self, "New certificate:", pw, self.compare)
        self.new.pack(fill="x", pady=2)

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=4)
        ttk.Checkbutton(bar, text="Show only differences", variable=self.only_diff, command=self._fill_table).pack(side="left")
        ttk.Button(bar, text="Swap", command=self.swap).pack(side="left", padx=8)
        ttk.Label(bar, text="Rows highlighted in orange differ. Double-click a row to see full values.",
                  foreground="#555").pack(side="left", padx=10)

        pane = ttk.PanedWindow(self, orient="vertical")
        pane.pack(fill="both", expand=True)

        sum_frame = ttk.LabelFrame(pane, text="Summary", padding=4)
        self.summary = ttk.Treeview(sum_frame, columns=("msg",), show="tree", height=7)
        self.summary.column("#0", width=110, stretch=False)
        self.summary.column("msg", width=800)
        _tag_colors(self.summary)
        self.summary.pack(fill="both", expand=True)
        pane.add(sum_frame, weight=1)

        tbl_frame = ttk.LabelFrame(pane, text="Side-by-side comparison", padding=4)
        self.table = ttk.Treeview(tbl_frame, columns=("field", "old", "new"), show="headings")
        for c, t, w in [("field", "Field", 160), ("old", "Current", 400), ("new", "New", 400)]:
            self.table.heading(c, text=t)
            self.table.column(c, width=w, anchor="w")
        _tag_colors(self.table)
        tsb = ttk.Scrollbar(tbl_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=tsb.set)
        self.table.pack(side="left", fill="both", expand=True)
        tsb.pack(side="left", fill="y")
        self.table.bind("<Double-1>", self._show_row)
        pane.add(tbl_frame, weight=3)

    def swap(self):
        for attr in ("certs",):
            a, b = getattr(self.old, attr), getattr(self.new, attr)
            setattr(self.old, attr, b)
            setattr(self.new, attr, a)
        po, pn = self.old.path.get(), self.new.path.get()
        self.old.path.set(pn)
        self.new.path.set(po)
        vo, vn = self.old.choice["values"], self.new.choice["values"]
        io, inn = self.old.choice.current(), self.new.choice.current()
        self.old.choice["values"], self.new.choice["values"] = vn, vo
        if vn:
            self.old.choice.current(inn)
        else:
            self.old.choice.set("")
        if vo:
            self.new.choice.current(io)
        else:
            self.new.choice.set("")
        self.compare()

    def compare(self):
        self.summary.delete(*self.summary.get_children())
        a, b = self.old.selected, self.new.selected
        if a is None or b is None:
            self.rows = []
            # show single-cert info so the user gets feedback right away
            single = a or b
            if single:
                sev, msg = single.validity_status()
                self.summary.insert("", "end", text=f"{SEV_ICON[sev]} {sev}",
                                    values=(f"{single.display_name}: {msg}",), tags=(sev,))
                self.rows = [cc.CompareRow(r.field, r.old if a else "", r.new if b else "")
                             for r in cc.compare(single, single)[0]]
            self._fill_table()
            return
        self.rows, findings = cc.compare(a, b)
        for f in findings:
            self.summary.insert("", "end", text=f"{SEV_ICON[f.severity]} {f.severity}", values=(f.message,), tags=(f.severity,))
        self._fill_table()

    def _fill_table(self):
        self.table.delete(*self.table.get_children())
        both = self.old.selected is not None and self.new.selected is not None
        for i, r in enumerate(self.rows):
            diff = both and not r.same and r.field != "Source file"
            if self.only_diff.get() and both and not diff:
                continue
            self.table.insert("", "end", iid=str(i), values=(r.field, r.old.replace("\n", ", "), r.new.replace("\n", ", ")),
                              tags=("diff",) if diff else ("same",))

    def _show_row(self, _evt=None):
        sel = self.table.selection()
        if not sel:
            return
        r = self.rows[int(sel[0])]
        win = tk.Toplevel(self)
        win.title(r.field)
        win.geometry("900x400")
        for col, (title, val) in enumerate((("Current", r.old), ("New", r.new))):
            fr = ttk.LabelFrame(win, text=title, padding=4)
            fr.grid(row=0, column=col, sticky="nsew", padx=4, pady=4)
            t = tk.Text(fr, wrap="word", font=("Courier New", 9))
            t.insert("1.0", val)
            t.configure(state="disabled")
            t.pack(fill="both", expand=True)
        win.columnconfigure(0, weight=1)
        win.columnconfigure(1, weight=1)
        win.rowconfigure(0, weight=1)


# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x820")
        self.minsize(900, 600)
        try:
            ttk.Style(self).theme_use("vista" if os.name == "nt" else "clam")
        except tk.TclError:
            pass
        pw = PasswordCache(self)
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)
        self.validate_tab = ValidateTab(nb, pw)
        self.compare_tab = CompareTab(nb, pw)
        nb.add(self.validate_tab, text="  Validate certificate / chain  ")
        nb.add(self.compare_tab, text="  Compare current vs new  ")


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
