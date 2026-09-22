"""TLS tunnel via pyOpenSSL memory BIO — outer and inner TEAP tunnels."""

from __future__ import annotations

from OpenSSL import SSL, crypto


class TLSTunnel:
    """Wraps an OpenSSL.SSL.Connection in memory BIO mode for EAP transport."""

    def __init__(self, client_cert_pem: str = "", client_key_pem: str = "",
                 ca_chain_pem: str = ""):
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_max_proto_version(SSL.TLS1_2_VERSION)
        ctx.set_min_proto_version(SSL.TLS1_2_VERSION)

        self.verify_error: str = ""

        if ca_chain_pem:
            for pem_block in _split_pem_chain(ca_chain_pem):
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_block)
                ctx.get_cert_store().add_cert(cert)

        if client_cert_pem and client_key_pem:
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, client_cert_pem.encode()
                                           if isinstance(client_cert_pem, str) else client_cert_pem)
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, client_key_pem.encode()
                                          if isinstance(client_key_pem, str) else client_key_pem)
            ctx.use_certificate(x509)
            ctx.use_privatekey(pkey)

        if ca_chain_pem:
            # Validate the server certificate against the supplied chain. There is
            # no hostname to check — the peer is reached over RADIUS, not DNS — so
            # this is chain/signature/validity verification only.
            def _verify_cb(_conn, _cert, errnum, _depth, ok):
                if not ok:
                    self.verify_error = (
                        f"server certificate verification failed "
                        f"(OpenSSL error {errnum})")
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
        except SSL.Error:
            self._established = False
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


def _split_pem_chain(chain_pem: str) -> list[bytes]:
    certs = []
    current = []
    for line in chain_pem.strip().splitlines():
        current.append(line)
        if "END CERTIFICATE" in line:
            certs.append("\n".join(current).encode())
            current = []
    return certs
