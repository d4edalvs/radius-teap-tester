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


# ── Full view ───────────────────────────────────────────────

_EKU_NAMES = {
    "serverAuth": "Server Authentication", "clientAuth": "Client Authentication",
    "codeSigning": "Code Signing", "emailProtection": "Secure Email",
    "timeStamping": "Time Stamping", "OCSPSigning": "OCSP Signing",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.5.7.3.13": "EAP over PPP", "1.3.6.1.5.5.7.3.14": "EAP over LAN",
}
_KEY_USAGES = (
    ("digital_signature", "Digital Signature"), ("content_commitment", "Non-Repudiation"),
    ("key_encipherment", "Key Encipherment"), ("data_encipherment", "Data Encipherment"),
    ("key_agreement", "Key Agreement"), ("key_cert_sign", "Certificate Sign"),
    ("crl_sign", "CRL Sign"),
)

_EXTENSION_NAMES = {
    "basicConstraints": "Basic Constraints", "subjectAltName": "Subject Alternative Name",
    "issuerAltName": "Issuer Alternative Name", "keyUsage": "Key Usage",
    "extendedKeyUsage": "Extended Key Usage", "subjectKeyIdentifier": "Subject Key Identifier",
    "authorityKeyIdentifier": "Authority Key Identifier",
    "cRLDistributionPoints": "CRL Distribution Points",
    "authorityInfoAccess": "Authority Information Access",
    "certificatePolicies": "Certificate Policies", "nameConstraints": "Name Constraints",
    "1.3.6.1.4.1.311.20.2": "Certificate Template Name",
    "1.3.6.1.4.1.311.21.7": "Certificate Template Information",
    "1.3.6.1.4.1.311.21.10": "Application Policies",
    "1.3.6.1.4.1.311.25.2": "SID (NTDS CA Security)",
}


def _oid_name(oid) -> str:
    name = getattr(oid, "_name", "")
    return name if name and name != "Unknown OID" else oid.dotted_string


def _colon_hex(data: bytes) -> str:
    return ":".join(f"{b:02X}" for b in data)


def _general_name(name) -> str:
    if isinstance(name, x509.DNSName):
        return f"DNS: {name.value}"
    if isinstance(name, x509.RFC822Name):
        return f"Email: {name.value}"
    if isinstance(name, x509.UniformResourceIdentifier):
        return f"URI: {name.value}"
    if isinstance(name, x509.IPAddress):
        return f"IP: {name.value}"
    if isinstance(name, x509.DirectoryName):
        return f"DirName: {name.value.rfc4514_string()}"
    if isinstance(name, x509.RegisteredID):
        return f"RID: {name.value.dotted_string}"
    if isinstance(name, x509.OtherName):
        if name.type_id.dotted_string == OID_UPN:
            return f"UPN: {_upn([name])}"
        return f"OtherName {name.type_id.dotted_string}: {name.value.hex()}"
    return str(name)


def _extension_lines(ext) -> list[str]:
    """One extension's value as readable lines, in the terms ISE and Windows use."""
    v = ext.value
    if isinstance(v, x509.SubjectAlternativeName):
        return [_general_name(n) for n in v]
    if isinstance(v, x509.KeyUsage):
        used = [label for attr, label in _KEY_USAGES if getattr(v, attr)]
        if v.key_agreement:
            used += [label for attr, label in (("encipher_only", "Encipher Only"),
                                               ("decipher_only", "Decipher Only"))
                     if getattr(v, attr)]
        return used
    if isinstance(v, x509.ExtendedKeyUsage):
        return [f"{_EKU_NAMES.get(_oid_name(o), _EKU_NAMES.get(o.dotted_string, _oid_name(o)))}"
                f" ({o.dotted_string})" for o in v]
    if isinstance(v, x509.BasicConstraints):
        out = [f"CA: {'yes' if v.ca else 'no'}"]
        if v.path_length is not None:
            out.append(f"Path length: {v.path_length}")
        return out
    if isinstance(v, x509.SubjectKeyIdentifier):
        return [_colon_hex(v.digest)]
    if isinstance(v, x509.AuthorityKeyIdentifier):
        out = [f"Key ID: {_colon_hex(v.key_identifier)}"] if v.key_identifier else []
        out += [f"Issuer: {_general_name(n)}" for n in v.authority_cert_issuer or []]
        if v.authority_cert_serial_number is not None:
            out.append(f"Serial: {format(v.authority_cert_serial_number, 'X')}")
        return out
    if isinstance(v, x509.CRLDistributionPoints):
        return [_general_name(n) for point in v for n in (point.full_name or [])]
    if isinstance(v, x509.AuthorityInformationAccess):
        names = {"OCSP": "OCSP", "caIssuers": "CA Issuers"}
        return [f"{names.get(_oid_name(d.access_method), _oid_name(d.access_method))}: "
                f"{_general_name(d.access_location)}" for d in v]
    if isinstance(v, x509.CertificatePolicies):
        return [p.policy_identifier.dotted_string
                + "".join(f" — {q}" for q in (p.policy_qualifiers or []) if isinstance(q, str))
                for p in v]
    if isinstance(v, x509.UnrecognizedExtension):
        return [v.value.hex()]
    return [str(v)]


def _public_key(cert) -> str:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    key = cert.public_key()
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


def inspect(pem: str) -> list[dict]:
    """Every field of every certificate in a stored bundle, leaf first.

    Only public material: a stored private key is never part of content_pem.
    """
    out = []
    for block in split_pem_chain(pem):
        cert = x509.load_pem_x509_certificate(block.encode())
        extensions = []
        for ext in cert.extensions:
            try:
                lines = _extension_lines(ext)
            except Exception:                         # an odd encoding must not
                lines = [str(ext.value)]              # take the whole page down
            name = _oid_name(ext.oid)
            extensions.append({"name": _EXTENSION_NAMES.get(name, name),
                               "oid": ext.oid.dotted_string,
                               "critical": ext.critical, "lines": lines})
        out.append({
            "subject": cert.subject.rfc4514_string(),
            "subject_rdns": [(a.rfc4514_attribute_name, a.value) for a in cert.subject],
            "issuer": cert.issuer.rfc4514_string(),
            "issuer_rdns": [(a.rfc4514_attribute_name, a.value) for a in cert.issuer],
            "version": cert.version.name,
            "serial": format(cert.serial_number, "X"),
            "signature_algorithm": _oid_name(cert.signature_algorithm_oid),
            "public_key": _public_key(cert),
            "valid_from": cert.not_valid_before_utc,
            "valid_to": cert.not_valid_after_utc,
            "self_signed": cert.subject == cert.issuer,
            "sha256": _colon_hex(cert.fingerprint(hashes.SHA256())),
            "sha1": _colon_hex(cert.fingerprint(hashes.SHA1())),
            "extensions": extensions,
            "pem": block,
        })
    return out
