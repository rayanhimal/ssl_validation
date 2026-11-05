"""Command line interface (handy for scripting / servers without a display)."""
from __future__ import annotations

import argparse
import getpass
import os

from . import certcore as cc


def _load(path: str) -> list[cc.CertInfo]:
    try:
        return cc.load_certificates(path)
    except cc.PasswordRequired:
        return cc.load_certificates(path, getpass.getpass(f"Password for {path}: "))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ssl_validator", description="Validate and compare SSL certificates")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate a certificate file / chain")
    v.add_argument("file")
    v.add_argument("--key", help="private key file to check against the leaf")
    v.add_argument("--no-folder", action="store_true", help="don't use other certs in the same folder")
    c = sub.add_parser("compare", help="compare current and new certificate")
    c.add_argument("current")
    c.add_argument("new")
    a = p.parse_args(argv)

    if a.cmd == "validate":
        certs = _load(a.file)
        pool = [] if a.no_folder else cc.load_folder_certs(os.path.dirname(os.path.abspath(a.file)), exclude=a.file)
        key = None
        if a.key:
            try:
                key = cc.load_private_key(a.key)
            except cc.PasswordRequired:
                key = cc.load_private_key(a.key, getpass.getpass(f"Password for {a.key}: "))
        res = cc.analyze(certs, extra_pool=pool, private_key=key)
        print(res.report_text())
        return 2 if res.worst == cc.ERROR else (1 if res.worst == cc.WARN else 0)

    old, new = cc.pick_leaf(_load(a.current)), cc.pick_leaf(_load(a.new))
    rows, findings = cc.compare(old, new)
    print("SUMMARY")
    for f in findings:
        print(f"  [{f.severity}] {f.message}")
    print()
    w = max(len(r.field) for r in rows)
    for r in rows:
        mark = "  " if r.same else "≠ "
        print(f"{mark}{r.field:<{w}} | current: {r.old.replace(chr(10), ', ')}")
        print(f"  {'':<{w}} | new:     {r.new.replace(chr(10), ', ')}")
    return 0
