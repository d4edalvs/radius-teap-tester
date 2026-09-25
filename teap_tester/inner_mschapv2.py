"""Inner EAP-MSCHAPv2 as run inside the TEAP tunnel.

A mixin for TEAPSession: it relies on the session's logging and send helpers,
and owns only what is specific to MS-CHAPv2. The cryptography is in
mschapv2.py.
"""

from __future__ import annotations

import struct

from . import mschapv2
from .types import EAPType, State, TEAPIdentityType

# RFC 2759 section 2 opcodes
MSCHAP_CHALLENGE = 1
MSCHAP_RESPONSE = 2
MSCHAP_SUCCESS = 3
MSCHAP_FAILURE = 4


class InnerMschapv2Mixin:

    def _password_for_current_identity(self) -> str:
        """The password for the leg being authenticated, if it has one.

        No falling back between legs: a machine leg holding a certificate and
        no password of its own must NAK toward EAP-TLS, not answer MS-CHAPv2
        with the user's password.
        """
        if self._current_identity_type == TEAPIdentityType.MACHINE:
            return self.config.machine_password
        return self.config.password

    async def _handle_inner_mschapv2(self, inner_eap: dict,
                                     extra_response: bytes = b"") -> bytes | None:
        """Answer an inner EAP-MSCHAPv2 request.

        The peer answers a Challenge with a Response, and a Success with a bare
        Success so the server knows the exchange completed.
        """
        payload = inner_eap["payload"]
        if not payload:
            return self._fail("Inner MSCHAPv2 packet is empty")
        opcode = payload[0]

        if opcode == MSCHAP_CHALLENGE:
            return await self._answer_mschap_challenge(payload, extra_response)

        if opcode == MSCHAP_SUCCESS:
            state = self._mschap_state
            if state:
                expected = mschapv2.generate_authenticator_response(
                    state["password"], state["nt_response"], state["peer_challenge"],
                    state["auth_challenge"], state["username"])
                # OpCode(1) + MS-CHAPv2-ID(1) + MS-Length(2) precede the message.
                received = payload[4:].decode("latin-1", "replace")
                if expected not in received:
                    # Mutual authentication failed: the server does not hold the
                    # password it claims to. Continuing would defeat the point.
                    return self._fail("Inner MSCHAPv2 authenticator response mismatch")
                self._log_msg("✓", "TEAP", "Inner MSCHAPv2 server authenticated")
                self._record_leg("MS-CHAPv2", state["username"])
                # The MSK derived here is what binds this method to the tunnel.
                self._inner_msk = mschapv2.session_key(state["password"],
                                                        state["nt_response"])
            self._log_msg("→", "TEAP", "Inner MSCHAPv2 Success")
            return await self._send_inner_eap(
                EAPType.MSCHAPV2, struct.pack("B", MSCHAP_SUCCESS), extra_response)

        if opcode == MSCHAP_FAILURE:
            raw = payload[4:].decode("latin-1", "replace").strip()
            self._log_msg("←", "TEAP",
                          f"Inner MSCHAPv2 Failure: {mschapv2.describe_failure(raw)}")
            self.state = State.FAILED
            return None

        return self._fail(f"Inner MSCHAPv2 unexpected opcode {opcode}")

    async def _answer_mschap_challenge(self, payload: bytes,
                                       extra_response: bytes) -> bytes | None:
        if len(payload) < 5:
            return self._fail("Inner MSCHAPv2 challenge truncated")
        value_size = payload[4]
        auth_challenge = payload[5:5 + value_size]
        if len(auth_challenge) != 16:
            return self._fail(
                f"Inner MSCHAPv2 challenge is {len(auth_challenge)} octets, expected 16")
        password = self._password_for_current_identity()
        if not password:
            return self._fail("Server asked for MSCHAPv2 but no password is configured")

        username = self._inner_identity()
        peer_challenge = mschapv2.new_peer_challenge()
        nt_response = mschapv2.generate_nt_response(
            auth_challenge, peer_challenge, username, password)

        # Remembered so the server's Success message can be checked.
        self._mschap_state = {
            "auth_challenge": auth_challenge, "peer_challenge": peer_challenge,
            "nt_response": nt_response, "username": username,
            "password": password, "id": payload[1] if len(payload) > 1 else 0,
        }

        value = peer_challenge + b"\x00" * 8 + nt_response + b"\x00"
        body = (struct.pack("BB", MSCHAP_RESPONSE, self._mschap_state["id"])
                + struct.pack("!H", 5 + len(value) + len(username))
                + struct.pack("B", len(value)) + value
                + username.encode("latin-1", "replace"))
        self._log_msg("←", "TEAP", "Inner MSCHAPv2 Challenge")
        self._log_msg("→", "TEAP", f"Inner MSCHAPv2 Response for \"{username}\"")
        return await self._send_inner_eap(EAPType.MSCHAPV2, body, extra_response)
