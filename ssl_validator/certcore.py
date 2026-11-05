"""Core logic: load certificates, build/validate chains, compare certificates.

This module has no GUI dependency so it can be used from the GUI, the CLI
and the tests.
"""

from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass, field
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

CERT_EXTENSIONS = {
    ".pem", ".crt", ".cer", ".cert", ".der", ".ca-bundle", ".bundle",
    ".p7b", ".p7c", ".pfx", ".p12", ".chain",
}
KEY_EXTENSIONS = {".key", ".pem"}

EXPIRY_WARNING_DAYS = 30

# Severity levels for findings
OK = "OK"
INFO = "INFO"
WARN = "WARNING"
ERROR = "ERROR"


class PasswordRequired(Exception):
    """Raised when a PKCS#12 (.pfx/.p12) file needs a password."""


class CertLoadError(Exception):
    pass


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------

@dataclass
class CertInfo:
    cert: x509.Certificate
    source: str  # file path the certificate came from
    index_in_file: int = 0

    # ---- identity -------------------------------------------------------
    @property
    def fingerprint_sha256(self) -> str:
        return _hex(self.cert.fingerprint(hashes.SHA256()))

    @property
    def fingerprint_sha1(self) -> str:
        return _hex(self.cert.fingerprint(hashes.SHA1()))

    @property
    def subject(self) -> str:
        return self.cert.subject.rfc4514_string()

    @property
    def issuer(self) -> str:
        return self.cert.issuer.rfc4514_string()

    @property
    def subject_cn(self) -> str:
        return _cn(self.cert.subject)

    @property
    def issuer_cn(self) -> str:
        return _cn(self.cert.issuer)

    @property
    def display_name(self) -> str:
        return self.subject_cn or self.subject or "(no subject)"

    @property
    def serial(self) -> str:
        return format(self.cert.serial_number, "X")

    # ---- validity -------------------------------------------------------
    @property
    def not_before(self) -> _dt.datetime:
        return _utc(self.cert, "not_valid_before")

    @property
    def not_after(self) -> _dt.datetime:
        return _utc(self.cert, "not_valid_after")

    def days_remaining(self, now: _dt.datetime | None = None) -> int:
        now = now or _now()
        return (self.not_after - now).days

    def validity_status(self, now: _dt.datetime | None = None) -> tuple[str, str]:
        now = now or _now()
        if now < self.not_before:
            return ERROR, f"Not yet valid (valid from {fmt_date(self.not_before)})"
        if now > self.not_after:
            return ERROR, f"EXPIRED on {fmt_date(self.not_after)} ({-self.days_remaining(now)} days ago)"
        days = self.days_remaining(now)
        if days <= EXPIRY_WARNING_DAYS:
            return WARN, f"Expires soon: {fmt_date(self.not_after)} ({days} days left)"
        return OK, f"Valid until {fmt_date(self.not_after)} ({days} days left)"

    # ---- role -----------------------------------------------------------
    @property
    def is_self_signed(self) -> bool:
        if self.cert.subject != self.cert.issuer:
            return False
        return signed_by(self.cert, self.cert)

    @property
    def is_ca(self) -> bool:
        bc = self._ext(x509.BasicConstraints)
        return bool(bc and bc.ca)

    @property
    def role(self) -> str:
        if self.is_self_signed:
            # v1 certificates have no extensions; treat old v1 self-signed certs as roots
            if self.is_ca or self.cert.version == x509.Version.v1:
                return "Root"
            return "Self-signed"
        if self.is_ca:
            return "Intermediate"
        return "Leaf"

    # ---- extensions -----------------------------------------------------
    def _ext(self, ext_type):
        try:
            return self.cert.extensions.get_extension_for_class(ext_type).value
        except (x509.ExtensionNotFound, ValueError):
            return None

    @property
    def san_dns(self) -> list[str]:
        san = self._ext(x509.SubjectAlternativeName)
        if not san:
            return []
        out = [f"DNS:{n}" for n in san.get_values_for_type(x509.DNSName)]
        out += [f"IP:{ip}" for ip in san.get_values_for_type(x509.IPAddress)]
        out += [f"email:{e}" for e in san.get_values_for_type(x509.RFC822Name)]
        out += [f"URI:{u}" for u in san.get_values_for_type(x509.UniformResourceIdentifier)]
        return out

    @property
    def key_description(self) -> str:
        return describe_key(self.cert.public_key())

    @property
    def signature_algorithm(self) -> str:
        try:
            h = self.cert.signature_hash_algorithm
            hname = h.name.upper() if h else ""
        except Exception:  # unsupported algorithm
            hname = ""
        oid_name = getattr(self.cert.signature_algorithm_oid, "_name", "") or self.cert.signature_algorithm_oid.dotted_string
        return f"{oid_name}" + (f" ({hname})" if hname and hname not in oid_name.upper() else "")

    @property
    def key_usage(self) -> list[str]:
        ku = self._ext(x509.KeyUsage)
        if not ku:
            return []
        names = []
        for attr, label in [
            ("digital_signature", "Digital Signature"),
            ("content_commitment", "Non Repudiation"),
            ("key_encipherment", "Key Encipherment"),
            ("data_encipherment", "Data Encipherment"),
            ("key_agreement", "Key Agreement"),
            ("key_cert_sign", "Certificate Sign"),
            ("crl_sign", "CRL Sign"),
        ]:
            if getattr(ku, attr):
                names.append(label)
        return names

    @property
    def extended_key_usage(self) -> list[str]:
        eku = self._ext(x509.ExtendedKeyUsage)
        if not eku:
            return []
        return [getattr(o, "_name", o.dotted_string) for o in eku]

    @property
    def subject_key_id(self) -> str:
        ski = self._ext(x509.SubjectKeyIdentifier)
        return _hex(ski.digest) if ski else ""

    @property
    def authority_key_id(self) -> str:
        aki = self._ext(x509.AuthorityKeyIdentifier)
        return _hex(aki.key_identifier) if aki and aki.key_identifier else ""

    @property
    def ca_issuers_urls(self) -> list[str]:
        aia = self._ext(x509.AuthorityInformationAccess)
        if not aia:
            return []
        return [
            d.access_location.value
            for d in aia
            if d.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(d.access_location, x509.UniformResourceIdentifier)
        ]

    @property
    def ocsp_urls(self) -> list[str]:
        aia = self._ext(x509.AuthorityInformationAccess)
        if not aia:
            return []
        return [
            d.access_location.value
            for d in aia
            if d.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
            and isinstance(d.access_location, x509.UniformResourceIdentifier)
        ]

    @property
    def crl_urls(self) -> list[str]:
        crl = self._ext(x509.CRLDistributionPoints)
        out = []
        for dp in crl or []:
            for n in dp.full_name or []:
                if isinstance(n, x509.UniformResourceIdentifier):
                    out.append(n.value)
        return out

    def public_key_bytes(self) -> bytes:
        return self.cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def to_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    def details_text(self, now: _dt.datetime | None = None) -> str:
        sev, validity = self.validity_status(now)
        lines = [
            f"Role:              {self.role}",
            f"Subject:           {self.subject}",
            f"Subject CN:        {self.subject_cn}",
            f"Issuer:            {self.issuer}",
            f"Issuer CN:         {self.issuer_cn}",
            f"Serial number:     {self.serial}",
            f"Valid from:        {fmt_date(self.not_before)}",
            f"Valid to:          {fmt_date(self.not_after)}",
            f"Status:            [{sev}] {validity}",
            f"Public key:        {self.key_description}",
            f"Signature alg.:    {self.signature_algorithm}",
            f"Is CA:             {'Yes' if self.is_ca else 'No'}",
            f"Key usage:         {', '.join(self.key_usage) or '-'}",
            f"Extended key usage:{' ' + ', '.join(self.extended_key_usage) if self.extended_key_usage else ' -'}",
            f"Subject Key ID:    {self.subject_key_id or '-'}",
            f"Authority Key ID:  {self.authority_key_id or '-'}",
            f"SHA-256 fingerprint: {self.fingerprint_sha256}",
            f"SHA-1 fingerprint:   {self.fingerprint_sha1}",
        ]
        san = self.san_dns
        lines.append(f"Subject Alt Names ({len(san)}):")
        lines += [f"    {s}" for s in san] or ["    -"]
        if self.ca_issuers_urls:
            lines.append("CA Issuers (download issuer cert from):")
            lines += [f"    {u}" for u in self.ca_issuers_urls]
        if self.ocsp_urls:
            lines.append("OCSP:")
            lines += [f"    {u}" for u in self.ocsp_urls]
        if self.crl_urls:
            lines.append("CRL:")
            lines += [f"    {u}" for u in self.crl_urls]
        lines.append(f"Source file:       {self.source}" + (f" (certificate #{self.index_in_file + 1})" if self.index_in_file else ""))
        return "\n".join(lines)


@dataclass
class Finding:
    severity: str
    message: str


@dataclass
class ChainResult:
    """Result of building/validating one chain starting at a leaf (or end) cert."""

    chain: list[CertInfo]  # leaf first, root last (as far as we could build it)
    complete: bool  # ends with a self-signed root
    missing_issuer: str = ""  # issuer DN we could not find
    missing_issuer_cn: str = ""
    findings: list[Finding] = field(default_factory=list)

    @property
    def worst(self) -> str:
        return worst_severity(f.severity for f in self.findings)


@dataclass
class Analysis:
    file_certs: list[CertInfo]
    chains: list[ChainResult]
    findings: list[Finding]  # file-level findings
    private_key_match: bool | None = None

    @property
    def worst(self) -> str:
        sev = [f.severity for f in self.findings]
        for c in self.chains:
            sev += [f.severity for f in c.findings]
        return worst_severity(sev)

    def report_text(self, now: _dt.datetime | None = None) -> str:
        out = []
        out.append(f"OVERALL RESULT: {self.worst}")
        out.append("")
        if self.findings:
            out.append("File checks:")
            out += [f"  [{f.severity}] {f.message}" for f in self.findings]
            out.append("")
        for n, c in enumerate(self.chains, 1):
            out.append(f"Chain #{n}: {'COMPLETE' if c.complete else 'INCOMPLETE'}")
            for depth, ci in enumerate(reversed(c.chain)):
                prefix = "  " + "   " * depth + "└─ "
                origin = "" if ci.source == self._main_source else f" (from {os.path.basename(ci.source)})"
                out.append(f"{prefix}[{ci.role}] {ci.display_name}{origin}")
            for f in c.findings:
                out.append(f"  [{f.severity}] {f.message}")
            out.append("")
        out.append("=" * 70)
        for ci in self.file_certs:
            out.append(ci.details_text(now))
            out.append("-" * 70)
        return "\n".join(out)

    @property
    def _main_source(self) -> str:
        return self.file_certs[0].source if self.file_certs else ""


SEVERITY_ORDER = {OK: 0, INFO: 1, WARN: 2, ERROR: 3}


def worst_severity(sevs: Iterable[str]) -> str:
    worst = OK
    for s in sevs:
        if SEVERITY_ORDER.get(s, 0) > SEVERITY_ORDER[worst]:
            worst = s
    return worst


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _utc(cert: x509.Certificate, attr: str) -> _dt.datetime:
    """Timezone-aware validity date, compatible with cryptography < 42."""
    val = getattr(cert, attr + "_utc", None)
    if val is None:
        import warnings as _w

        with _w.catch_warnings():
            _w.simplefilter("ignore")
            val = getattr(cert, attr).replace(tzinfo=_dt.timezone.utc)
    return val


def _hex(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else ""


def fmt_date(d: _dt.datetime) -> str:
    return d.strftime("%Y-%m-%d %H:%M:%S UTC")


def describe_key(key) -> str:
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size} bits"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name} ({key.key_size} bits)"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA {key.key_size} bits"
    return type(key).__name__


def signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """True if `cert` was issued (name match + valid signature) by `issuer`."""
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def is_cert_file(path: str) -> bool:
    name = os.path.basename(path).lower()
    _, ext = os.path.splitext(name)
    return ext in CERT_EXTENSIONS or ext in KEY_EXTENSIONS or name.endswith(".ca-bundle")


def load_certificates(path: str, password: str | None = None) -> list[CertInfo]:
    """Load all certificates from a file (PEM, DER, PKCS#7, PKCS#12)."""
    with open(path, "rb") as fh:
        data = fh.read()
    certs = parse_certificates(data, password=password, filename=path)
    return [CertInfo(c, path, i) for i, c in enumerate(certs)]


def parse_certificates(data: bytes, password: str | None = None, filename: str = "") -> list[x509.Certificate]:
    ext = os.path.splitext(filename.lower())[1]
    stripped = data.strip()

    if b"-----BEGIN" in data:
        certs: list[x509.Certificate] = []
        if b"-----BEGIN CERTIFICATE-----" in data or b"-----BEGIN TRUSTED CERTIFICATE-----" in data:
            try:
                certs = x509.load_pem_x509_certificates(_normalize_pem(data))
            except ValueError:
                # Fallback: parse block by block, skipping broken ones
                certs = _parse_pem_blocks(data)
        if b"-----BEGIN PKCS7-----" in data:
            try:
                certs += pkcs7.load_pem_pkcs7_certificates(data)
            except ValueError:
                pass
        if certs:
            return certs
        if b"PRIVATE KEY-----" in data:
            raise CertLoadError("File contains a private key but no certificate.")
        if b"CERTIFICATE REQUEST-----" in data:
            raise CertLoadError("File is a certificate signing request (CSR), not a certificate.")
        raise CertLoadError("No certificate found in PEM file.")

    # Binary formats
    if ext in (".pfx", ".p12"):
        return _load_pkcs12(data, password)
    try:
        return [x509.load_der_x509_certificate(stripped)]
    except ValueError:
        pass
    try:
        return list(pkcs7.load_der_pkcs7_certificates(stripped))
    except Exception:
        pass
    if data[:1] == b"\x30" and ext not in (".crt", ".cer", ".der", ".pem"):
        return _load_pkcs12(data, password)
    raise CertLoadError("Unrecognised file format (expected PEM, DER, PKCS#7 or PKCS#12).")


def _normalize_pem(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"TRUSTED CERTIFICATE", b"CERTIFICATE")


def _parse_pem_blocks(data: bytes) -> list[x509.Certificate]:
    data = _normalize_pem(data)
    out = []
    begin, end = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
    pos = 0
    while True:
        s = data.find(begin, pos)
        if s < 0:
            break
        e = data.find(end, s)
        if e < 0:
            break
        try:
            out.append(x509.load_pem_x509_certificate(data[s:e + len(end)]))
        except ValueError:
            pass
        pos = e + len(end)
    return out


def _load_pkcs12(data: bytes, password: str | None) -> list[x509.Certificate]:
    pw = password.encode() if password else None
    if not data[:1] == b"\x30":  # PKCS#12 is a DER SEQUENCE
        raise CertLoadError("Not a PKCS#12 file.")
    try:
        p12 = pkcs12.load_pkcs12(data, pw)
    except ValueError as exc:
        # cryptography gives the same error for "wrong/missing password" and
        # "corrupt file"; a DER SEQUENCE we can't open is most likely encrypted.
        raise PasswordRequired(str(exc)) from exc
    certs = []
    if p12.cert:
        certs.append(p12.cert.certificate)
    certs += [c.certificate for c in p12.additional_certs]
    if not certs:
        raise CertLoadError("PKCS#12 file contains no certificates.")
    return certs


def load_pkcs12_key(path: str, password: str | None):
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        p12 = pkcs12.load_pkcs12(data, password.encode() if password else None)
    except ValueError:
        return None
    return p12.key


def load_private_key(path: str, password: str | None = None):
    with open(path, "rb") as fh:
        data = fh.read()
    pw = password.encode() if password else None
    try:
        if b"-----BEGIN" in data:
            return serialization.load_pem_private_key(data, pw)
        return serialization.load_der_private_key(data, pw)
    except TypeError as exc:  # password missing / not needed
        if "encrypted" in str(exc).lower() or "password was not given" in str(exc).lower():
            raise PasswordRequired(str(exc)) from exc
        raise CertLoadError(str(exc)) from exc
    except ValueError as exc:
        if pw is not None and ("decrypt" in str(exc).lower() or "password" in str(exc).lower()):
            raise PasswordRequired(str(exc)) from exc
        raise CertLoadError(f"Could not read private key: {exc}") from exc


def private_key_matches(key, cert: x509.Certificate) -> bool:
    pub = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    cpub = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pub == cpub


def scan_folder(folder: str, recursive: bool = True) -> list[str]:
    """Return candidate certificate files in a folder."""
    out = []
    if recursive:
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                p = os.path.join(root, f)
                if is_cert_file(p):
                    out.append(p)
    else:
        for f in os.listdir(folder):
            p = os.path.join(folder, f)
            if os.path.isfile(p) and is_cert_file(p):
                out.append(p)
    return sorted(out, key=str.lower)


def load_folder_certs(folder: str, exclude: str | None = None) -> list[CertInfo]:
    """Load every readable certificate in a folder (non-recursive), silently skipping errors."""
    out = []
    for p in scan_folder(folder, recursive=False):
        if exclude and os.path.abspath(p) == os.path.abspath(exclude):
            continue
        try:
            out += load_certificates(p)
        except Exception:
            continue
    return out


# --------------------------------------------------------------------------
# Chain building & validation
# --------------------------------------------------------------------------

def _dedupe(certs: Iterable[CertInfo]) -> list[CertInfo]:
    seen = set()
    out = []
    for c in certs:
        fp = c.fingerprint_sha256
        if fp not in seen:
            seen.add(fp)
            out.append(c)
    return out


def find_issuer(ci: CertInfo, pool: list[CertInfo]) -> CertInfo | None:
    candidates = [p for p in pool if p.cert.subject == ci.cert.issuer and p.fingerprint_sha256 != ci.fingerprint_sha256]
    # Prefer a currently-valid candidate if there are several (cross-signs / renewals)
    now = _now()
    candidates.sort(key=lambda p: (not (p.not_before <= now <= p.not_after),))
    for cand in candidates:
        if signed_by(ci.cert, cand.cert):
            return cand
    return None


def build_chain(start: CertInfo, pool: list[CertInfo]) -> ChainResult:
    chain = [start]
    current = start
    missing = ""
    missing_cn = ""
    while True:
        if current.is_self_signed:
            break
        if len(chain) > 15:
            break
        used = {c.fingerprint_sha256 for c in chain}
        issuer = find_issuer(current, [p for p in pool if p.fingerprint_sha256 not in used])
        if issuer is None:
            missing = current.issuer
            missing_cn = current.issuer_cn
            break
        chain.append(issuer)
        current = issuer
    complete = chain[-1].is_self_signed
    return ChainResult(chain=chain, complete=complete, missing_issuer=missing, missing_issuer_cn=missing_cn)


def _end_entities(certs: list[CertInfo]) -> list[CertInfo]:
    """Certificates that did not issue any other certificate in the list."""
    ends = []
    for c in certs:
        issued_other = any(
            o is not c and o.cert.issuer == c.cert.subject and signed_by(o.cert, c.cert) for o in certs
        )
        if not issued_other:
            ends.append(c)
    return ends


def analyze(
    file_certs: list[CertInfo],
    extra_pool: list[CertInfo] | None = None,
    private_key=None,
    now: _dt.datetime | None = None,
) -> Analysis:
    """Analyse the certificates found in one file.

    extra_pool: other certificates (e.g. the rest of the folder) that may be used to
    complete the chain.
    """
    now = now or _now()
    findings: list[Finding] = []
    file_certs_u = _dedupe(file_certs)
    if len(file_certs_u) != len(file_certs):
        findings.append(Finding(WARN, f"File contains {len(file_certs) - len(file_certs_u)} duplicate certificate(s)."))

    roles = [c.role for c in file_certs_u]
    findings.append(Finding(INFO, (
        f"File contains {len(file_certs_u)} certificate(s): "
        f"{roles.count('Leaf')} leaf, {roles.count('Intermediate')} intermediate, "
        f"{roles.count('Root') + roles.count('Self-signed')} root/self-signed."
    )))

    pool = _dedupe(file_certs_u + (extra_pool or []))

    # Chains start at end-entity certs present in the file.
    starts = _end_entities(file_certs_u) or file_certs_u[:1]
    chains = []
    for s in starts:
        res = build_chain(s, pool)
        _check_chain(res, file_certs_u, now)
        chains.append(res)

    # Certificates in the file that are not part of any chain
    in_chains = {c.fingerprint_sha256 for r in chains for c in r.chain}
    for c in file_certs_u:
        if c.fingerprint_sha256 not in in_chains:
            findings.append(Finding(WARN, f"Certificate '{c.display_name}' is not related to the chain (extra/unrelated certificate)."))

    # Order check: servers (nginx/Apache/HAProxy) expect leaf first, then issuers in order.
    if len(file_certs_u) > 1 and len(chains) == 1:
        expected = [c.fingerprint_sha256 for c in chains[0].chain if c.fingerprint_sha256 in {f.fingerprint_sha256 for f in file_certs_u}]
        actual = [c.fingerprint_sha256 for c in file_certs_u if c.fingerprint_sha256 in set(expected)]
        if expected == actual:
            findings.append(Finding(OK, "Certificates in the file are in the correct order (leaf → intermediate(s) → root)."))
        elif expected[::-1] == actual:
            findings.append(Finding(WARN, "Certificates are in REVERSE order (root first). Most servers expect leaf first, then intermediates."))
        else:
            findings.append(Finding(WARN, "Certificates in the file are not in chain order. Expected: leaf → intermediate(s) → root."))

    pk_match = None
    if private_key is not None and chains:
        leaf = chains[0].chain[0]
        pk_match = private_key_matches(private_key, leaf.cert)
        if pk_match:
            findings.append(Finding(OK, f"Private key MATCHES certificate '{leaf.display_name}'."))
        else:
            findings.append(Finding(ERROR, f"Private key does NOT match certificate '{leaf.display_name}'."))

    return Analysis(file_certs=file_certs_u, chains=chains, findings=findings, private_key_match=pk_match)


def _check_chain(res: ChainResult, file_certs: list[CertInfo], now: _dt.datetime) -> None:
    f = res.findings
    file_fps = {c.fingerprint_sha256 for c in file_certs}
    leaf = res.chain[0]

    # Composition summary
    if leaf.role == "Leaf":
        f.append(Finding(OK, f"Leaf (server) certificate present: {leaf.display_name}"))
    elif leaf.role in ("Root", "Self-signed"):
        f.append(Finding(WARN, f"Only a self-signed certificate was found ('{leaf.display_name}') — no leaf certificate."))
    else:
        f.append(Finding(WARN, f"No leaf certificate: the chain starts at CA certificate '{leaf.display_name}'."))

    intermediates = [c for c in res.chain[1:] if not c.is_self_signed]
    for c in intermediates:
        if c.fingerprint_sha256 in file_fps:
            f.append(Finding(OK, f"Intermediate present in file: {c.display_name}"))
        else:
            f.append(Finding(WARN, f"Intermediate '{c.display_name}' is NOT in the file (found in {os.path.basename(c.source)})."))

    if res.complete:
        root = res.chain[-1]
        if root is leaf:
            pass
        elif root.fingerprint_sha256 in file_fps:
            f.append(Finding(OK, f"Root certificate present in file: {root.display_name}"))
        else:
            f.append(Finding(INFO, f"Root '{root.display_name}' is not in the file (found in {os.path.basename(root.source)})."))
        f.append(Finding(OK, "Chain is COMPLETE and all signatures are valid."))
    else:
        last = res.chain[-1]
        if last.is_ca or len(res.chain) > 1:
            what = "intermediate or root"
        else:
            what = "intermediate"
        msg = f"Chain INCOMPLETE: issuer of '{last.display_name}' is missing ({what}). Missing issuer: {res.missing_issuer}"
        f.append(Finding(ERROR, msg))
        if last.ca_issuers_urls:
            f.append(Finding(INFO, f"The missing issuer can be downloaded from: {', '.join(last.ca_issuers_urls)}"))

    # Per-certificate validity
    for c in res.chain:
        sev, msg = c.validity_status(now)
        if sev != OK:
            f.append(Finding(sev, f"{c.role} '{c.display_name}': {msg}"))
    sev, msg = leaf.validity_status(now)
    if sev == OK:
        f.append(Finding(OK, f"{leaf.role} '{leaf.display_name}': {msg}"))

    # Validity nesting: leaf should not outlive its issuer
    for child, parent in zip(res.chain, res.chain[1:]):
        if child.not_after > parent.not_after:
            f.append(Finding(WARN, f"'{child.display_name}' expires after its issuer '{parent.display_name}' ({fmt_date(parent.not_after)})."))

    # Leaf checks
    if leaf.role == "Leaf":
        if not leaf.san_dns:
            f.append(Finding(WARN, "Leaf certificate has no Subject Alternative Name (browsers require SAN)."))
        elif leaf.subject_cn and not any(s.split(":", 1)[1].lower() == leaf.subject_cn.lower() for s in leaf.san_dns):
            f.append(Finding(INFO, f"Subject CN '{leaf.subject_cn}' is not listed in the SAN."))
        eku = leaf.cert.extensions
        try:
            ekus = eku.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            if ExtendedKeyUsageOID.SERVER_AUTH not in ekus:
                f.append(Finding(INFO, "Leaf certificate is not marked for TLS server authentication (no serverAuth EKU)."))
        except x509.ExtensionNotFound:
            pass

    # Crypto strength
    for c in res.chain:
        key = c.cert.public_key()
        if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
            f.append(Finding(ERROR, f"'{c.display_name}' uses a weak RSA key ({key.key_size} bits)."))
        try:
            h = c.cert.signature_hash_algorithm
        except Exception:
            h = None
        if h is not None and h.name in ("md5", "sha1") and not c.is_self_signed:
            f.append(Finding(WARN, f"'{c.display_name}' is signed with weak hash {h.name.upper()}."))


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

@dataclass
class CompareRow:
    field: str
    old: str
    new: str

    @property
    def same(self) -> bool:
        return self.old == self.new


def pick_leaf(certs: list[CertInfo]) -> CertInfo:
    """Pick the most relevant certificate (the leaf) from a list."""
    leaves = [c for c in certs if c.role == "Leaf"]
    if leaves:
        return leaves[0]
    ends = _end_entities(certs)
    return ends[0] if ends else certs[0]


def compare(old: CertInfo, new: CertInfo, now: _dt.datetime | None = None) -> tuple[list[CompareRow], list[Finding]]:
    now = now or _now()

    def validity(c: CertInfo) -> str:
        return c.validity_status(now)[1]

    rows = [
        CompareRow("Role", old.role, new.role),
        CompareRow("Subject CN", old.subject_cn, new.subject_cn),
        CompareRow("Subject", old.subject, new.subject),
        CompareRow("Issuer CN", old.issuer_cn, new.issuer_cn),
        CompareRow("Issuer", old.issuer, new.issuer),
        CompareRow("Valid from", fmt_date(old.not_before), fmt_date(new.not_before)),
        CompareRow("Valid to", fmt_date(old.not_after), fmt_date(new.not_after)),
        CompareRow("Status", validity(old), validity(new)),
        CompareRow("Days remaining", str(old.days_remaining(now)), str(new.days_remaining(now))),
        CompareRow("Subject Alt Names", "\n".join(old.san_dns), "\n".join(new.san_dns)),
        CompareRow("Public key", old.key_description, new.key_description),
        CompareRow("Signature algorithm", old.signature_algorithm, new.signature_algorithm),
        CompareRow("Key usage", ", ".join(old.key_usage), ", ".join(new.key_usage)),
        CompareRow("Extended key usage", ", ".join(old.extended_key_usage), ", ".join(new.extended_key_usage)),
        CompareRow("Serial number", old.serial, new.serial),
        CompareRow("Authority Key ID", old.authority_key_id, new.authority_key_id),
        CompareRow("Subject Key ID", old.subject_key_id, new.subject_key_id),
        CompareRow("SHA-256 fingerprint", old.fingerprint_sha256, new.fingerprint_sha256),
        CompareRow("Source file", old.source, new.source),
    ]

    f: list[Finding] = []
    if old.fingerprint_sha256 == new.fingerprint_sha256:
        f.append(Finding(WARN, "Both files contain the SAME certificate (identical fingerprint)."))
        return rows, f

    f.append(Finding(OK if old.subject_cn == new.subject_cn else WARN,
                     f"Subject CN {'unchanged' if old.subject_cn == new.subject_cn else 'CHANGED'}: "
                     f"{old.subject_cn!r} → {new.subject_cn!r}"))
    if old.subject != new.subject:
        f.append(Finding(INFO, "Full subject DN changed (O/OU/L/ST/C fields differ)."))

    old_san, new_san = set(old.san_dns), set(new.san_dns)
    if old_san == new_san:
        f.append(Finding(OK, f"SANs identical ({len(new_san)} names)."))
    else:
        removed = sorted(old_san - new_san)
        added = sorted(new_san - old_san)
        if removed:
            f.append(Finding(WARN, f"SAN names REMOVED in new certificate: {', '.join(removed)}"))
        if added:
            f.append(Finding(INFO, f"SAN names ADDED in new certificate: {', '.join(added)}"))

    if old.issuer == new.issuer:
        f.append(Finding(OK, f"Same issuer: {new.issuer_cn or new.issuer}"))
    else:
        f.append(Finding(WARN, f"Issuer CHANGED: {old.issuer_cn or old.issuer} → {new.issuer_cn or new.issuer}. "
                               "Make sure the new intermediate chain is installed."))

    sev, msg = new.validity_status(now)
    f.append(Finding(sev, f"New certificate: {msg}"))
    if new.not_after > old.not_after:
        delta = (new.not_after - old.not_after).days
        f.append(Finding(OK, f"New certificate expires {delta} days later than the current one."))
    elif new.not_after < old.not_after:
        f.append(Finding(WARN, "New certificate expires EARLIER than the current one."))

    if old.public_key_bytes() == new.public_key_bytes():
        f.append(Finding(INFO, "Same key pair is reused (existing private key works with the new certificate)."))
    else:
        f.append(Finding(INFO, "New key pair: you need the NEW private key for the new certificate."))

    if old.key_description != new.key_description:
        f.append(Finding(INFO, f"Key type/size changed: {old.key_description} → {new.key_description}"))
    return rows, f
