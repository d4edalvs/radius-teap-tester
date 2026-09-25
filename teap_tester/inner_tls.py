"""Inner EAP-TLS (RFC 5216) as run inside the TEAP tunnel.

A mixin for TEAPSession: it relies on the session's tunnel, logging and
send helpers, and owns only what is specific to EAP-TLS.
"""

from __future__ import annotations

from .tunnel import TLSTunnel
from .types import EAPType, State, TEAPIdentityType

TLS_FLAG_LENGTH = 0x80     # a 4-octet TLS Message Length follows the flags


def tls_data(payload: bytes) -> bytes:
    """The TLS bytes of an EAP-TLS payload, past the flags and any length.

    A payload that is only the flags octet carries no data: it is an ACK.
    """
    if len(payload) <= 1:
        return b""
    if payload[0] & TLS_FLAG_LENGTH and len(payload) > 5:
        return payload[5:]
    return payload[1:]


class InnerTlsMixin:

    def _inner_tls_credentials(self) -> tuple[str, str]:
        """Certificate and key for the leg; a machine leg falls back to the user's."""
        cfg = self.config
        if self._current_identity_type == TEAPIdentityType.MACHINE:
            return (cfg.machine_cert_pem or cfg.client_cert_pem,
                    cfg.machine_key_pem or cfg.client_key_pem)
        return cfg.client_cert_pem, cfg.client_key_pem

    async def _send_inner_tls(self, data: bytes,
                              extra_response: bytes = b"") -> bytes | None:
        # Flags 0: the client never fragments, so neither L nor M is set.
        return await self._send_inner_eap(EAPType.TLS, b"\x00" + data, extra_response)

    async def _handle_inner_tls(self, inner_eap: dict,
                                extra_response: bytes = b"") -> bytes | None:
        body = tls_data(inner_eap["payload"])

        if not self._inner_tunnel:
            self._log_msg("←", "TEAP", "Inner EAP-TLS start")
            self.state = State.INNER_TLS_HANDSHAKE
            cert, key = self._inner_tls_credentials()
            self._inner_tunnel = TLSTunnel(client_cert_pem=cert, client_key_pem=key,
                                           ca_chain_pem=self.config.ca_chain_pem)
            client_hello = self._inner_tunnel.start_handshake()
            outgoing = self._inner_tunnel.feed_data(body) if body else None
            out_data = outgoing or client_hello
            self._log_msg("→", "TEAP", f"Inner TLS ClientHello ({len(out_data)} bytes)")
            return await self._send_inner_tls(out_data, extra_response)

        if not body:
            self._log_msg("←", "TEAP", "Inner EAP-TLS empty (ACK)")
            return await self._send_inner_tls(b"", extra_response)

        self._log_msg("←", "TEAP", f"Inner TLS data ({len(body)} bytes)")
        outgoing = self._inner_tunnel.feed_data(body)

        if self._inner_tunnel.is_established:
            self._log_msg("✓", "TEAP", "Inner TLS established")
            self._record_leg("EAP-TLS", self._inner_identity())
            self.state = State.INNER_TLS_DONE
            try:
                self._inner_msk = self._inner_tunnel.export_inner_msk()
            except Exception as e:
                # Carry on so the server's verdict is still observable, but a
                # zero MSK means the Crypto-Binding will almost surely fail.
                self._inner_msk = b"\x00" * 64
                self._log_msg("!", "TEAP", f"Inner MSK export failed ({e}); "
                                           "using zeros — expect Crypto-Binding rejection")

        if outgoing:
            self._log_msg("→", "TEAP", f"Inner TLS data ({len(outgoing)} bytes)")
        return await self._send_inner_tls(outgoing or b"", extra_response)
