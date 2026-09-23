"""Certificate parsing for the Certificates page."""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12


def split_pem_chain(pem: str) -> list[str]:
    """Split a concatenated PEM bundle into individual certificate blocks."""
    marker = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    out, rest = [], pem
    while marker in rest:
        start = rest.index(marker)
        stop = rest.index(end, start) + len(end)
        out.append(rest[start:stop])
        rest = rest[stop:]
    return out


def describe(pem: str) -> dict:
    """Subject/issuer/serial/thumbprint/validity of the leaf certificate."""
    cert = x509.load_pem_x509_certificate(pem.encode())
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "thumbprint": cert.fingerprint(hashes.SHA256()).hex(),
        "valid_from": cert.not_valid_before_utc.replace(tzinfo=None),
        "valid_to": cert.not_valid_after_utc.replace(tzinfo=None),
        "self_signed": cert.subject == cert.issuer,
    }


def load_pkcs12(blob: bytes, passphrase: str = "") -> tuple[str, str, list[str]]:
    """Return (leaf PEM, private key PEM, [extra chain PEMs]) from a .p12/.pfx."""
    pwd = passphrase.encode() if passphrase else None
    key, cert, extra = pkcs12.load_key_and_certificates(blob, pwd)
    if cert is None:
        raise ValueError("PKCS#12 contains no certificate")
    leaf = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = ""
    if key is not None:
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
    chain = [c.public_bytes(serialization.Encoding.PEM).decode() for c in (extra or [])]
    return leaf, key_pem, chain


def key_matches_cert(cert_pem: str, key_pem: str) -> bool:
    """True when the private key belongs to the certificate."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    return (cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            == key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo))


def expiry_state(valid_to: dt.datetime | None) -> str:
    """'expired', 'expiring' (within 30 days), or 'ok'."""
    if valid_to is None:
        return "ok"
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    if valid_to < now:
        return "expired"
    if valid_to - now < dt.timedelta(days=30):
        return "expiring"
    return "ok"
