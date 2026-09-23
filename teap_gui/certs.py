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


# Microsoft UPN, carried as an otherName in the SAN. This is what a Windows
# supplicant presents as the user identity.
OID_UPN = "1.3.6.1.4.1.311.20.2.3"


def _common_name(cert) -> str:
    from cryptography.x509.oid import NameOID
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def _upn(san) -> str:
    """Decode the DER UTF8String inside a UPN otherName, if present."""
    for name in san:
        if isinstance(name, x509.OtherName) and name.type_id.dotted_string == OID_UPN:
            raw = name.value
            if len(raw) >= 2 and raw[0] == 0x0C:        # UTF8String
                return raw[2:2 + raw[1]].decode("utf-8", "replace")
            return raw.decode("utf-8", "replace")
    return ""


def identity_from_cert(pem: str, kind: str = "user") -> str:
    """Derive the identity a supplicant would present for this certificate.

    User: UPN, else SAN email, else CN.
    Machine: host/<SAN DNS>, else host/<CN> — the form ISE expects for
    machine authentication.
    """
    cert = x509.load_pem_x509_certificate(split_pem_chain(pem)[0].encode())
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None

    if kind == "machine":
        dns = san.get_values_for_type(x509.DNSName) if san else []
        host = dns[0] if dns else _common_name(cert)
        return f"host/{host}" if host else ""

    if san:
        upn = _upn(san)
        if upn:
            return upn
        emails = san.get_values_for_type(x509.RFC822Name)
        if emails:
            return emails[0]
    return _common_name(cert)
