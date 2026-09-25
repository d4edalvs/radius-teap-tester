"""TLS tunnel via pyOpenSSL memory BIO — outer and inner TEAP tunnels."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from OpenSSL import SSL, crypto


# OpenSSL X509_V_ERR codes a misconfigured trust chain actually produces.
_VERIFY_REASONS = {
    2: "unable to get issuer certificate",
    7: "certificate signature failure",
    9: "certificate is not yet valid",
    10: "certificate has expired",
    18: "self-signed certificate",
    19: "self-signed certificate in chain",
    20: "unable to get local issuer certificate",
    21: "unable to verify the first certificate",
    24: "invalid CA certificate",
    26: "unsupported certificate purpose",
}


class ServerCertificateError(Exception):
    """The server's certificate did not validate against the trusted chain.

    `alert` holds the TLS alert record OpenSSL produced for the server, so the
    caller can deliver it: a server told why the handshake ended logs the
    reason at once instead of timing the client out.
    """

    def __init__(self, message: str, alert: bytes = b""):
        super().__init__(message)
        self.alert = alert


class TLSTunnel:
    """Wraps an OpenSSL.SSL.Connection in memory BIO mode for EAP transport."""

    def __init__(self, client_cert_pem: str = "", client_key_pem: str = "",
                 ca_chain_pem: str = ""):
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)

        self.verify_error: str = ""

        if ca_chain_pem:
            store = ctx.get_cert_store()
            for cert in _load_certs(ca_chain_pem):
                # The store still takes only pyOpenSSL's X509; converting at
                # the boundary keeps everything else on cryptography's types.
                store.add_cert(crypto.X509.from_cryptography(cert))

        if client_cert_pem and client_key_pem:
            leaf, *chain = _load_certs(client_cert_pem)
            ctx.use_certificate(leaf)
            ctx.use_privatekey(load_pem_private_key(_as_bytes(client_key_pem),
                                                    password=None))
            # Anything after the leaf is sent as the client's chain. Which certs
            # end up here is the caller's choice (full chain, chain without the
            # root, or leaf only) — servers differ on what they want to see.
            for extra in chain:
                ctx.add_extra_chain_cert(extra)

        if ca_chain_pem:
            # Validate the server certificate against the supplied chain. There is
            # no hostname to check — the peer is reached over RADIUS, not DNS — so
            # this is chain/signature/validity verification only.
            def _verify_cb(_conn, cert, errnum, depth, ok):
                # OpenSSL reports every problem it finds; the first is the cause.
                if not ok and not self.verify_error:
                    reason = _VERIFY_REASONS.get(errnum, f"OpenSSL verify error {errnum}")
                    subject = cert.to_cryptography().subject.rfc4514_string()
                    self.verify_error = (f"server certificate not trusted: {reason} "
                                         f"(depth {depth}: {subject})")
                return bool(ok)

            ctx.set_verify(SSL.VERIFY_PEER, _verify_cb)
        else:
            ctx.set_verify(SSL.VERIFY_NONE, lambda *_: True)

        self._conn = SSL.Connection(ctx, None)
        self._conn.set_connect_state()
        self._established = False

    def start_handshake(self) -> bytes:
        try:
            self._conn.do_handshake()
        except SSL.WantReadError:
            pass
        return self._bio_read()

    def feed_data(self, incoming: bytes) -> bytes | None:
        self._conn.bio_write(incoming)
        try:
            self._conn.do_handshake()
            self._established = True
        except SSL.WantReadError:
            pass
        except SSL.Error as exc:
            self._established = False
            if self.verify_error:
                raise ServerCertificateError(self.verify_error,
                                             alert=self._bio_read()) from exc
            raise

        outgoing = self._bio_read()
        return outgoing if outgoing else None

    @property
    def is_established(self) -> bool:
        return self._established

    def encrypt(self, plaintext: bytes) -> bytes:
        self._conn.write(plaintext)
        return self._bio_read()

    def decrypt(self, ciphertext: bytes) -> bytes:
        self._conn.bio_write(ciphertext)
        return self.read_pending()

    def read_pending(self) -> bytes:
        """Application data already received but not yet read.

        A server may send its first TLVs in the same flight that finishes the
        handshake; they sit decrypted-but-unread once do_handshake returns.
        """
        chunks = []
        while True:
            try:
                chunk = self._conn.read(16384)
                if chunk:
                    chunks.append(chunk)
                else:
                    break
            except SSL.WantReadError:
                break
            except SSL.ZeroReturnError:
                break
        return b"".join(chunks)

    def get_cipher_name(self) -> str:
        cipher = self._conn.get_cipher_name()
        return cipher if cipher else ""

    def export_session_key_seed(self) -> bytes:
        return self._conn.export_keying_material(
            b"EXPORTER: teap session key seed", 40, None
        )

    def export_inner_msk(self) -> bytes:
        return self._conn.export_keying_material(
            b"client EAP encryption", 64, None
        )

    def export_inner_emsk(self) -> bytes:
        """The EMSK: octets 64..128 of the same export as the MSK."""
        return self._conn.export_keying_material(
            b"client EAP encryption", 128, None
        )[64:128]

    def _bio_read(self) -> bytes:
        chunks = []
        while True:
            try:
                chunk = self._conn.bio_read(16384)
                if chunk:
                    chunks.append(chunk)
                else:
                    break
            except SSL.WantReadError:
                break
        return b"".join(chunks)


def _as_bytes(pem: str | bytes) -> bytes:
    return pem.encode() if isinstance(pem, str) else pem


def _load_certs(pem: str | bytes) -> list[x509.Certificate]:
    """Every certificate in a PEM bundle, in order.

    Text between blocks (openssl's Bag Attributes, subject lines) and blocks
    that are not certificates are skipped. No certificate at all is an error.
    """
    return x509.load_pem_x509_certificates(_as_bytes(pem))
