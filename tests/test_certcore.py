import datetime as dt
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssl_validator import certcore as cc  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(cn, issuer_cert=None, issuer_key=None, ca=False, days=365, start_offset=-1,
              sans=None, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = _name(cn)
    issuer = issuer_cert.subject if issuer_cert else subject
    signer = issuer_key or key
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW + dt.timedelta(days=start_offset))
         .not_valid_after(NOW + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if not ca:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in (sans or [cn])]), critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    cert = b.sign(signer, hashes.SHA256())
    return cert, key


@pytest.fixture(scope="module")
def pki():
    root, root_key = make_cert("Test Root CA", ca=True, days=3650)
    inter, inter_key = make_cert("Test Intermediate CA", root, root_key, ca=True, days=1825)
    leaf, leaf_key = make_cert("www.example.com", inter, inter_key, days=365,
                               sans=["www.example.com", "example.com"])
    return dict(root=root, root_key=root_key, inter=inter, inter_key=inter_key, leaf=leaf, leaf_key=leaf_key)


def pem(*certs):
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def sev_msgs(analysis):
    out = [(f.severity, f.message) for f in analysis.findings]
    for c in analysis.chains:
        out += [(f.severity, f.message) for f in c.findings]
    return out


def test_full_chain(tmp_path, pki):
    p = write(tmp_path, "full.pem", pem(pki["leaf"], pki["inter"], pki["root"]))
    certs = cc.load_certificates(p)
    assert [c.role for c in certs] == ["Leaf", "Intermediate", "Root"]
    a = cc.analyze(certs)
    assert len(a.chains) == 1 and a.chains[0].complete
    assert a.worst in (cc.OK, cc.INFO)
    assert any("correct order" in m for _, m in sev_msgs(a))


def test_reverse_order(tmp_path, pki):
    p = write(tmp_path, "rev.pem", pem(pki["root"], pki["inter"], pki["leaf"]))
    a = cc.analyze(cc.load_certificates(p))
    assert a.chains[0].complete
    assert any("REVERSE" in m for _, m in sev_msgs(a))


def test_missing_intermediate(tmp_path, pki):
    p = write(tmp_path, "leaf.crt", pem(pki["leaf"]))
    a = cc.analyze(cc.load_certificates(p))
    assert not a.chains[0].complete
    assert a.worst == cc.ERROR
    assert "Test Intermediate CA" in a.chains[0].missing_issuer


def test_leaf_and_intermediate_without_root(tmp_path, pki):
    p = write(tmp_path, "chain.crt", pem(pki["leaf"], pki["inter"]))
    a = cc.analyze(cc.load_certificates(p))
    assert not a.chains[0].complete
    assert "Test Root CA" in a.chains[0].missing_issuer


def test_chain_completed_from_folder(tmp_path, pki):
    leaf = write(tmp_path, "server.crt", pem(pki["leaf"]))
    write(tmp_path, "intermediate.cer", pki["inter"].public_bytes(serialization.Encoding.DER))
    write(tmp_path, "root.pem", pem(pki["root"]))
    pool = cc.load_folder_certs(str(tmp_path), exclude=leaf)
    a = cc.analyze(cc.load_certificates(leaf), extra_pool=pool)
    assert a.chains[0].complete
    assert any("NOT in the file" in m for _, m in sev_msgs(a))


def test_der_and_pkcs12(tmp_path, pki):
    d = write(tmp_path, "leaf.der", pki["leaf"].public_bytes(serialization.Encoding.DER))
    assert cc.load_certificates(d)[0].subject_cn == "www.example.com"
    pfx = pkcs12.serialize_key_and_certificates(
        b"x", pki["leaf_key"], pki["leaf"], [pki["inter"]],
        serialization.BestAvailableEncryption(b"secret"))
    pp = write(tmp_path, "bundle.pfx", pfx)
    with pytest.raises(cc.PasswordRequired):
        cc.load_certificates(pp)
    certs = cc.load_certificates(pp, password="secret")
    assert [c.role for c in certs] == ["Leaf", "Intermediate"]
    key = cc.load_pkcs12_key(pp, "secret")
    assert cc.private_key_matches(key, pki["leaf"])


def test_private_key_match(tmp_path, pki):
    kp = write(tmp_path, "server.key", pki["leaf_key"].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key = cc.load_private_key(kp)
    a = cc.analyze([cc.CertInfo(pki["leaf"], "x")], private_key=key)
    assert a.private_key_match is True
    other = ec.generate_private_key(ec.SECP256R1())
    a = cc.analyze([cc.CertInfo(pki["leaf"], "x")], private_key=other)
    assert a.private_key_match is False


def test_expired_detected(pki):
    old, _ = make_cert("old.example.com", pki["inter"], pki["inter_key"], days=-1, start_offset=-400)
    a = cc.analyze([cc.CertInfo(old, "x"), cc.CertInfo(pki["inter"], "x")])
    assert any(s == cc.ERROR and "EXPIRED" in m for s, m in sev_msgs(a))


def test_compare(pki):
    cur, _ = make_cert("www.example.com", pki["inter"], pki["inter_key"], days=20,
                       sans=["www.example.com", "old.example.com"])
    new, _ = make_cert("www.example.com", pki["inter"], pki["inter_key"], days=400,
                       sans=["www.example.com", "api.example.com"])
    rows, findings = cc.compare(cc.CertInfo(cur, "cur.crt"), cc.CertInfo(new, "new.crt"))
    by = {r.field: r for r in rows}
    assert by["Subject CN"].same
    assert not by["Valid to"].same
    msgs = " | ".join(f.message for f in findings)
    assert "REMOVED" in msgs and "old.example.com" in msgs
    assert "ADDED" in msgs and "api.example.com" in msgs
    assert "later" in msgs
    assert "New key pair" in msgs


def test_pick_leaf(pki):
    certs = [cc.CertInfo(pki["root"], "x"), cc.CertInfo(pki["inter"], "x"), cc.CertInfo(pki["leaf"], "x")]
    assert cc.pick_leaf(certs).subject_cn == "www.example.com"


def test_scan_folder(tmp_path, pki):
    write(tmp_path, "a.crt", pem(pki["leaf"]))
    write(tmp_path, "notes.txt", b"hello")
    (tmp_path / "sub").mkdir()
    write(tmp_path / "sub", "b.pem", pem(pki["root"]))
    files = [os.path.basename(f) for f in cc.scan_folder(str(tmp_path))]
    assert files == ["a.crt", "b.pem"]


def test_non_cert_file(tmp_path):
    p = write(tmp_path, "junk.crt", b"not a certificate")
    with pytest.raises(cc.CertLoadError):
        cc.load_certificates(p)
