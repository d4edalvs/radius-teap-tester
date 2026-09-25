"""TEAP session orchestrator — the main protocol loop."""

from __future__ import annotations

import struct
import time

from OpenSSL import SSL

from .types import (
    EAPCode,
    EAPType,
    RadiusAttr,
    RadiusCode,
    State,
    TEAPIdentityType,
    TEAPResultStatus,
    TEAPTLVType,
    TEAPTestConfig,
    TEAPResult,
    LogEntry,
)
from . import radius as rad
from . import eap
from . import tlv
from .inner_mschapv2 import InnerMschapv2Mixin
from .inner_tls import InnerTlsMixin
from .tunnel import ServerCertificateError, TLSTunnel
from .crypto_binding import (
    compute_session_keys,
    build_crypto_binding_response,
    parse_crypto_binding,
)


def build_request_attrs(config, eap_message: bytes = b"", *,
                        outer_identity: str = "", connect_info: str = "",
                        radius_state: bytes | None = None
                        ) -> list[tuple[int, bytes]]:
    """Attributes carried by an Access-Request.

    Shared with anything that needs to show what will be sent before sending
    it; a separate implementation would drift from the real one.
    """
    import socket
    nas_ip = config.source_ip or socket.gethostbyname(socket.gethostname())
    try:
        nas_ip_bytes = socket.inet_aton(nas_ip)
    except OSError:
        nas_ip_bytes = socket.inet_aton("0.0.0.0")

    attrs: list[tuple[int, bytes]] = [
        (RadiusAttr.USER_NAME, (outer_identity or config.identity).encode()),
        (RadiusAttr.NAS_IP_ADDRESS, nas_ip_bytes),
        (RadiusAttr.NAS_PORT, struct.pack("!I", config.nas_port)),
        (RadiusAttr.NAS_PORT_TYPE, struct.pack("!I", config.nas_port_type)),
        (RadiusAttr.SERVICE_TYPE, struct.pack("!I", 2)),    # Framed
        (RadiusAttr.FRAMED_MTU, struct.pack("!I", config.framed_mtu)),
        (RadiusAttr.CALLING_STATION_ID, config.calling_station_id.encode()),
        (RadiusAttr.CONNECT_INFO, (connect_info or "CONNECT Ethernet").encode()),
    ]
    if eap_message:
        attrs.append((RadiusAttr.EAP_MESSAGE, eap_message))
    if config.nas_identifier:
        attrs.append((RadiusAttr.NAS_IDENTIFIER, config.nas_identifier.encode()))
    attrs.extend(config.extra_attrs)
    if config.called_station_id:
        attrs.append((RadiusAttr.CALLED_STATION_ID, config.called_station_id.encode()))
    if radius_state:
        attrs.append((RadiusAttr.STATE, radius_state))
    return attrs


class TEAPSession(InnerTlsMixin, InnerMschapv2Mixin):

    def __init__(self, config: TEAPTestConfig):
        self.config = config
        self.state = State.INIT
        self._secret = config.radius_secret.encode()
        self._eap_id = 0
        self._radius_id = 0
        self._radius_state: bytes | None = None
        self._authenticator = rad.make_authenticator()
        self._start_time = 0.0
        self._log: list[LogEntry] = []
        self._outer_tunnel: TLSTunnel | None = None
        self._inner_tunnel: TLSTunnel | None = None
        self._fragment_asm = eap.FragmentAssembler()
        self._session_key_seed: bytes = b""
        self._reply_attrs: dict[int, str | list[str]] = {}
        self._reply_code: int = 0
        self._inner_msk: bytes = b""
        self._mschap_state: dict = {}
        self._s_imck: bytes = b""
        self._s_imck_emsk: bytes = b""
        self._cmk: bytes = b""
        self._crypto_binding_done = False
        self._inner_eap_id = 0
        self._server_outer_tlvs: bytes = b""
        self._emsk_cmk: bytes = b""
        self._current_identity_type: int = 0  # 1=User, 2=Machine
        self._legs: list[dict] = []

    async def run(self) -> TEAPResult:
        self._start_time = time.monotonic()
        self._log_msg("→", "RADIUS", f"Starting TEAP auth as '{self._outer_identity()}'")

        try:
            eap_resp = await self._send_identity()
            if not eap_resp:
                return self._make_failure("No response to Identity")

            while self.state not in (State.DONE, State.FAILED):
                eap_resp = await self._process_response(eap_resp)
                if eap_resp is None and self.state not in (State.DONE, State.FAILED):
                    return self._make_failure("Unexpected end of conversation")

        except TimeoutError as e:
            return self._make_failure(f"Timeout: {e}")
        except ServerCertificateError as e:
            return self._make_failure(
                f"{e} — is the trusted chain the one that signs the server's "
                "EAP certificate?")
        except SSL.Error as e:
            return self._make_failure(f"TLS error: {e}")
        except Exception as e:
            # The type matters: a KeyError or struct.error stringifies to
            # almost nothing on its own.
            return self._make_failure(f"Error: {type(e).__name__}: {e}")

        duration = time.monotonic() - self._start_time
        if self.state == State.DONE:
            self._log_msg("✓", "TEAP", f"Authentication completed in {duration:.3f}s")
            return TEAPResult(
                success=True, output=self._format_log(),
                duration=duration, log_entries=list(self._log),
                reply_attrs=dict(self._reply_attrs),
                legs=list(self._legs),
            )
        return self._make_failure("Authentication failed")

    # ── Identity ────────────────────────────────────────────

    async def _send_identity(self) -> bytes | None:
        identity_eap = eap.encode_identity_response(self._eap_id, self._outer_identity())
        self._log_msg("→", "RADIUS",
                      f"Access-Request (EAP-Response/Identity \"{self._outer_identity()}\") [eap_id={self._eap_id}]")
        return await self._radius_exchange(identity_eap)

    # ── Main dispatch ───────────────────────────────────────

    async def _process_response(self, radius_data: bytes) -> bytes | None:
        resp = rad.decode_response(radius_data, self._secret, self._authenticator)
        self._radius_state = resp.get("state")
        code = resp["code"]

        if code == RadiusCode.ACCESS_ACCEPT:
            eap_msg = resp.get("eap_message")
            if eap_msg:
                eap_pkt = eap.decode_eap(eap_msg)
                if eap_pkt["code"] == EAPCode.SUCCESS:
                    self._log_msg("←", "RADIUS", "Access-Accept (EAP-Success)")
                    self.state = State.DONE
                    return None
            self._log_msg("←", "RADIUS", "Access-Accept")
            self.state = State.DONE
            return None

        if code == RadiusCode.ACCESS_REJECT:
            eap_msg = resp.get("eap_message")
            if eap_msg:
                eap_pkt = eap.decode_eap(eap_msg)
                if eap_pkt["code"] == EAPCode.FAILURE:
                    self._log_msg("←", "RADIUS", "Access-Reject (EAP-Failure)")
            else:
                self._log_msg("←", "RADIUS", "Access-Reject")
            self.state = State.FAILED
            return None

        if code != RadiusCode.ACCESS_CHALLENGE:
            return self._fail(f"Unexpected RADIUS code: {code}")

        eap_msg = resp.get("eap_message")
        if not eap_msg:
            return self._fail("Access-Challenge with no EAP-Message")

        eap_pkt = eap.decode_eap(eap_msg)

        if eap_pkt["code"] == EAPCode.SUCCESS:
            self._log_msg("←", "RADIUS", "EAP-Success in Challenge (unusual)")
            self.state = State.DONE
            return None

        if eap_pkt["code"] == EAPCode.FAILURE:
            self._log_msg("←", "RADIUS", "EAP-Failure")
            self.state = State.FAILED
            return None

        if eap_pkt["code"] != EAPCode.REQUEST:
            return self._fail(f"Expected EAP-Request, got code {eap_pkt['code']}")

        self._eap_id = eap_pkt["id"]

        if eap_pkt["type"] == EAPType.IDENTITY:
            self._log_msg("←", "EAP", "Identity request (retransmit)")
            return await self._send_identity()

        if eap_pkt["type"] != EAPType.TEAP:
            return self._fail(f"Expected EAP-TEAP, got type {eap_pkt['type']}")

        return await self._handle_teap(eap_pkt)

    # ── TEAP outer handling ─────────────────────────────────

    async def _handle_teap(self, eap_pkt: dict) -> bytes | None:
        teap_data = eap.decode_teap_request(eap_pkt["payload"])

        if teap_data["start"]:
            return await self._handle_teap_start(teap_data)

        assembled = self._fragment_asm.feed(teap_data)
        if self._fragment_asm.needs_ack:
            self._log_msg("→", "TEAP", "Fragment ACK")
            ack = eap.encode_teap_response(self._eap_id, 0)
            return await self._radius_exchange(ack)

        if assembled is None:
            return self._fail("Fragment assembly returned None unexpectedly")

        if not self._outer_tunnel or not self._outer_tunnel.is_established:
            return await self._tls_handshake_step(assembled)

        return await self._handle_tunnel_data(assembled)

    async def _handle_teap_start(self, teap_data: dict) -> bytes | None:
        authority_id = teap_data["data"]
        # Authority-ID data: first 4 bytes are a length prefix, skip them
        self._server_outer_tlvs = authority_id[4:] if len(authority_id) > 4 else authority_id
        self._log_msg("←", "TEAP",
                      f"TEAP-Start (authority_id={authority_id.hex()})")
        self.state = State.TLS_HANDSHAKE

        # No client cert in outer TLS — matches Windows behavior.
        # Client certs are used only in inner EAP-TLS methods.
        self._outer_tunnel = TLSTunnel(
            ca_chain_pem=self.config.ca_chain_pem,
        )
        client_hello = self._outer_tunnel.start_handshake()
        self._log_msg("→", "TEAP", f"ClientHello ({len(client_hello)} bytes)")
        resp = eap.encode_teap_response_with_length(
            self._eap_id, 0, len(client_hello), client_hello
        )
        return await self._radius_exchange(resp)

    async def _tls_handshake_step(self, tls_data: bytes) -> bytes | None:
        self._log_msg("←", "TEAP", f"TLS handshake data ({len(tls_data)} bytes)")
        outgoing = self._outer_tunnel.feed_data(tls_data)

        if self._outer_tunnel.is_established:
            self._log_msg("✓", "TEAP", "Outer TLS tunnel established")
            self.state = State.TUNNEL_UP
            self._session_key_seed = self._outer_tunnel.export_session_key_seed()

            if outgoing:
                resp = eap.encode_teap_response(self._eap_id, 0, outgoing)
                return await self._radius_exchange(resp)
            resp = eap.encode_teap_response(self._eap_id, 0)
            return await self._radius_exchange(resp)

        if outgoing:
            self._log_msg("→", "TEAP", f"TLS handshake ({len(outgoing)} bytes)")
            return await self._send_fragmented(outgoing)

        resp = eap.encode_teap_response(self._eap_id, 0)
        return await self._radius_exchange(resp)

    # ── Tunnel data handling (TLVs inside TLS) ──────────────

    async def _handle_tunnel_data(self, ciphertext: bytes) -> bytes | None:
        plaintext = self._outer_tunnel.decrypt(ciphertext)
        if not plaintext:
            self._log_msg("←", "TEAP", "Empty tunnel payload — sending ACK")
            resp = eap.encode_teap_response(self._eap_id, 0)
            return await self._radius_exchange(resp)

        tlvs = tlv.decode_tlvs(plaintext)
        return await self._dispatch_tlvs(tlvs)

    async def _dispatch_tlvs(self, tlvs: list) -> bytes | None:
        tlv_types = {t[0] for t in tlvs}
        tlv_map = {t[0]: t[2] for t in tlvs}
        type_names = ", ".join(f"{t[0]}({len(t[2])}b)" for t in tlvs)

        # Result + PAC TLV: acknowledge it; a final Result follows
        if TEAPTLVType.RESULT in tlv_types and TEAPTLVType.PAC in tlv_types:
            return await self._handle_result_pac(tlv_map)

        # Result + Crypto-Binding → final handshake
        if TEAPTLVType.RESULT in tlv_types and TEAPTLVType.CRYPTO_BINDING in tlv_types:
            return await self._handle_final_result(tlv_map)

        # Intermediate-Result + Crypto-Binding. Must precede the Crypto-Binding
        # test below: the broader condition would otherwise shadow this one and
        # an Intermediate-Result(Failure) would be silently ignored.
        if TEAPTLVType.INTERMEDIATE_RESULT in tlv_types and TEAPTLVType.CRYPTO_BINDING in tlv_types:
            return await self._handle_intermediate_result_crypto(tlv_map)

        # Crypto-Binding request alone
        if TEAPTLVType.CRYPTO_BINDING in tlv_types:
            return await self._handle_crypto_binding(tlv_map)

        # Identity-Type may share a packet with EAP-Payload, so check it first
        if TEAPTLVType.IDENTITY_TYPE in tlv_types:
            return await self._handle_identity_type(tlv_map)

        # EAP-Payload (inner EAP) without Identity-Type
        if TEAPTLVType.EAP_PAYLOAD in tlv_types:
            return await self._handle_inner_eap(tlv_map)

        # Error TLV
        if 5 in tlv_types:  # TEAPTLVType.ERROR = 5
            err_val = struct.unpack("!I", tlv_map[5][:4])[0] if len(tlv_map[5]) >= 4 else 0
            self._log_msg("←", "TEAP", f"Error TLV: code={err_val}")

        # Result alone (final)
        if TEAPTLVType.RESULT in tlv_types:
            result_val = struct.unpack("!H", tlv_map[TEAPTLVType.RESULT][:2])[0]
            if result_val == TEAPResultStatus.SUCCESS:
                self._log_msg("←", "TEAP", "Result(Success)")
                self.state = State.DONE
                response_data = tlv.result_tlv(TEAPResultStatus.SUCCESS)
                encrypted = self._outer_tunnel.encrypt(response_data)
                resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
                self._log_msg("→", "TEAP", "Result(Success) [final]")
                return await self._radius_exchange(resp)
            self._log_msg("←", "TEAP", "Result(Failure)")
            self.state = State.FAILED
            return None

        type_names = ", ".join(str(t) for t in tlv_types)
        self._log_msg("←", "TEAP", f"Unhandled TLVs: {type_names}")
        resp = eap.encode_teap_response(self._eap_id, 0)
        return await self._radius_exchange(resp)

    # ── Identity-Type handling ──────────────────────────────

    async def _handle_identity_type(self, tlv_map: dict) -> bytes | None:
        id_type = struct.unpack("!H", tlv_map[TEAPTLVType.IDENTITY_TYPE][:2])[0]
        self._current_identity_type = id_type
        type_name = "Machine" if id_type == TEAPIdentityType.MACHINE else "User"
        self._log_msg("←", "TEAP", f"Identity-Type request: {type_name}")

        if not self._has_credential_for(id_type):
            # RFC 7170 section 4.2.3: answer with an identity type we do have.
            # The server then either authenticates that one instead, asks for
            # something else, or applies its policy — its decision, not ours.
            # Failing here would break single-identity TEAP against a server
            # whose policy merely offers chaining.
            other = (TEAPIdentityType.USER if id_type == TEAPIdentityType.MACHINE
                     else TEAPIdentityType.MACHINE)
            if not self._has_credential_for(other):
                return self._fail(
                    "Server requested a {} identity and no credential of either "
                    "type is configured".format(type_name))
            other_name = "Machine" if other == TEAPIdentityType.MACHINE else "User"
            self._current_identity_type = other
            self.state = State.INNER_IDENTITY
            self._inner_tunnel = None
            self._log_msg("→", "TEAP",
                          f"No {type_name} identity configured — "
                          f"offering {other_name} instead")
            encrypted = self._outer_tunnel.encrypt(tlv.identity_type_tlv(other))
            resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
            return await self._radius_exchange(resp)
        self.state = State.INNER_IDENTITY
        # Reset inner tunnel for new inner method
        self._inner_tunnel = None

        response_tlv = tlv.identity_type_tlv(TEAPIdentityType(id_type))

        if TEAPTLVType.EAP_PAYLOAD in tlv_map:
            return await self._handle_inner_eap(tlv_map, extra_response=response_tlv)

        encrypted = self._outer_tunnel.encrypt(response_tlv)
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        self._log_msg("→", "TEAP", f"Identity-Type response: {type_name}")
        return await self._radius_exchange(resp)

    # ── Inner EAP handling ──────────────────────────────────

    async def _handle_inner_eap(self, tlv_map: dict,
                                 extra_response: bytes = b"") -> bytes | None:
        eap_data = tlv_map[TEAPTLVType.EAP_PAYLOAD]
        inner_eap = eap.decode_eap(eap_data)

        if inner_eap["code"] == EAPCode.SUCCESS:
            self._log_msg("←", "TEAP", "Inner EAP-Success")
            self.state = State.INNER_TLS_DONE
            if extra_response:
                encrypted = self._outer_tunnel.encrypt(extra_response)
                resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
                return await self._radius_exchange(resp)
            resp = eap.encode_teap_response(self._eap_id, 0)
            return await self._radius_exchange(resp)

        if inner_eap["code"] == EAPCode.FAILURE:
            self._log_msg("←", "TEAP", "Inner EAP-Failure")
            self.state = State.FAILED
            return None

        if inner_eap["code"] != EAPCode.REQUEST:
            return self._fail(f"Inner EAP unexpected code: {inner_eap['code']}")

        self._inner_eap_id = inner_eap["id"]

        if inner_eap["type"] == EAPType.IDENTITY:
            return await self._handle_inner_identity(inner_eap, extra_response)

        if inner_eap["type"] == EAPType.TLS:
            return await self._handle_inner_tls(inner_eap, extra_response)

        if (inner_eap["type"] == EAPType.MSCHAPV2
                and self._password_for_current_identity()):
            return await self._handle_inner_mschapv2(inner_eap, extra_response)

        # NAK toward whichever method this identity is configured for.
        proposed = inner_eap["type"]
        want = (EAPType.MSCHAPV2 if self._password_for_current_identity()
                else EAPType.TLS)
        self._log_msg("←", "TEAP",
                      f"Inner EAP method {proposed} proposed — sending NAK for {want.name}")
        return await self._send_inner_eap(EAPType.NAK, struct.pack("B", want),
                                          extra_response)

    # ── Shared by the inner methods (inner_tls.py, inner_mschapv2.py) ──

    def _inner_identity(self) -> str:
        if self._current_identity_type == TEAPIdentityType.MACHINE:
            return self.config.machine_identity or self.config.identity
        return self.config.identity

    def _record_leg(self, method: str, identity: str) -> None:
        """Note that an inner method ran for the current identity type."""
        self._legs.append({
            "identity_type": ("machine"
                              if self._current_identity_type == TEAPIdentityType.MACHINE
                              else "user"),
            "method": method,
            "identity": identity,
            "crypto_binding": False,
        })

    def _bind_current_leg(self) -> None:
        """Mark the most recent leg as cryptographically bound to the tunnel."""
        if self._legs:
            self._legs[-1]["crypto_binding"] = True

    def _has_credential_for(self, id_type: int) -> bool:
        """Whether any credential is configured for this identity type."""
        if id_type == TEAPIdentityType.MACHINE:
            return bool(self.config.machine_cert_pem or self.config.machine_password)
        return bool(self.config.client_cert_pem or self.config.password)

    async def _send_inner_eap(self, eap_type: int, body: bytes,
                              extra_response: bytes = b"") -> bytes | None:
        inner = eap.encode_eap(EAPCode.RESPONSE, self._inner_eap_id, eap_type, body)
        payload = extra_response + tlv.eap_payload_tlv(inner)
        encrypted = self._outer_tunnel.encrypt(payload)
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        return await self._radius_exchange(resp)

    async def _handle_inner_identity(self, inner_eap: dict,
                                      extra_response: bytes = b"") -> bytes | None:
        identity = self._inner_identity()
        self._log_msg("←", "TEAP", "Inner EAP-Identity request")
        self._log_msg("→", "TEAP", f"Inner EAP-Identity response: \"{identity}\"")
        self.state = State.INNER_IDENTITY
        return await self._send_inner_eap(EAPType.IDENTITY, identity.encode(),
                                          extra_response)

    # ── Crypto-Binding ──────────────────────────────────────

    async def _handle_crypto_binding(self, tlv_map: dict) -> bytes | None:
        cb_value = tlv_map[TEAPTLVType.CRYPTO_BINDING]
        parsed = parse_crypto_binding(cb_value)
        if "error" in parsed:
            return self._fail(parsed["error"])

        self._log_msg("←", "TEAP",
                      f"Crypto-Binding request (ver={parsed['version']}, "
                      f"recv_ver={parsed['received_version']}, "
                      f"flags={parsed['flags']}, sub={parsed['sub_type']}, "
                      f"nonce={parsed['nonce'][:8].hex()}...)")

        # Detect TLS cipher suite hash for PRF and MAC
        cipher = self._outer_tunnel.get_cipher_name() if self._outer_tunnel else ""
        hash_alg = "sha384" if "SHA384" in cipher.upper() else "sha256"
        self._hash_alg = hash_alg

        # S-IMCK computation: chain from previous S-IMCK (or session_key_seed for first round)
        from .crypto_binding import compute_imck as _compute_imck, tls_prf
        if not self._s_imck:
            # First Crypto-Binding round — start from session key seed
            self._s_imck = self._session_key_seed[:40]
            self._s_imck_emsk = self._session_key_seed[:40]

        isk = self._inner_msk[:32] if self._inner_msk else b"\x00" * 32

        # MSK chain
        imck = _compute_imck(self._s_imck, isk, hash_alg)
        self._s_imck = imck[:40]
        self._cmk = imck[40:60]

        # EMSK chain
        inner_emsk = b""
        if self._inner_tunnel:
            try:
                inner_emsk = self._inner_tunnel.export_inner_emsk()
            except Exception as e:
                self._log_msg("!", "TEAP", f"Inner EMSK export unavailable ({e}); "
                                           "sending the MSK Compound MAC only")
        if inner_emsk:
            emsk_imsk = tls_prf(inner_emsk, b"TEAPbindkey@ietf.org",
                                b"\x00\x00\x40", 32, hash_alg)
            emsk_imck = _compute_imck(self._s_imck_emsk, emsk_imsk, hash_alg)
            self._s_imck_emsk = emsk_imck[:40]
            self._emsk_cmk = emsk_imck[40:60]
        else:
            self._emsk_cmk = b""

        cb_response = build_crypto_binding_response(
            cb_value, self._cmk, hash_alg,
            server_outer_tlvs=self._server_outer_tlvs,
            emsk_cmk=self._emsk_cmk,
        )
        self._crypto_binding_done = True
        self._bind_current_leg()

        response_data = (
            tlv.encode_tlv(TEAPTLVType.CRYPTO_BINDING, True, cb_response)
            + tlv.intermediate_result_tlv(TEAPResultStatus.SUCCESS)
        )
        encrypted = self._outer_tunnel.encrypt(response_data)
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        self._log_msg("→", "TEAP", "Intermediate-Result(Success) + Crypto-Binding(Response)")
        self.state = State.CRYPTO_BINDING
        return await self._radius_exchange(resp)

    async def _handle_intermediate_result_crypto(self, tlv_map: dict) -> bytes | None:
        ir_val = struct.unpack("!H", tlv_map[TEAPTLVType.INTERMEDIATE_RESULT][:2])[0]
        status = "Success" if ir_val == TEAPResultStatus.SUCCESS else "Failure"
        self._log_msg("←", "TEAP", f"Intermediate-Result({status}) + Crypto-Binding")

        if ir_val != TEAPResultStatus.SUCCESS:
            self.state = State.FAILED
            return None

        return await self._handle_crypto_binding(tlv_map)

    # ── Result + PAC ────────────────────────────────────────

    async def _handle_result_pac(self, tlv_map: dict) -> bytes | None:
        result_val = struct.unpack("!H", tlv_map[TEAPTLVType.RESULT][:2])[0]
        pac = tlv.parse_pac_tlv(tlv_map[TEAPTLVType.PAC])
        pac_size = len(tlv_map[TEAPTLVType.PAC])

        detail = f"{pac_size} bytes"
        if "pac_lifetime" in pac:
            detail += f", lifetime={pac['pac_lifetime']}"
        if "pac_a_id" in pac:
            detail += f", a_id={pac['pac_a_id'].hex()[:32]}"
        status = "Success" if result_val == TEAPResultStatus.SUCCESS else "Failure"
        self._log_msg("←", "TEAP", f"Result({status}) + PAC TLV ({detail})")

        if result_val != TEAPResultStatus.SUCCESS:
            self.state = State.FAILED
            return None

        self.state = State.RESULT_PAC

        # Acknowledge the PAC with Result(Success); the server then sends the
        # final Result, so keep processing rather than terminating here.
        response_data = tlv.result_tlv(TEAPResultStatus.SUCCESS)
        encrypted = self._outer_tunnel.encrypt(response_data)
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        self._log_msg("→", "TEAP", "Result(Success) [PAC acknowledged]")
        return await self._radius_exchange(resp)

    # ── Final Result + Crypto-Binding ───────────────────────

    async def _handle_final_result(self, tlv_map: dict) -> bytes | None:
        result_val = struct.unpack("!H", tlv_map[TEAPTLVType.RESULT][:2])[0]
        status = "Success" if result_val == TEAPResultStatus.SUCCESS else "Failure"

        cb_value = tlv_map[TEAPTLVType.CRYPTO_BINDING]
        parsed = parse_crypto_binding(cb_value)
        self._log_msg("←", "TEAP",
                      f"Result({status}) + Crypto-Binding "
                      f"(ver={parsed.get('version')}, flags={parsed.get('flags')}, "
                      f"sub={parsed.get('sub_type')})")

        if result_val != TEAPResultStatus.SUCCESS:
            self.state = State.FAILED
            return None

        if not self._cmk:
            self._s_imck, self._cmk = compute_session_keys(
                self._session_key_seed, self._inner_msk
            )

        cb_response = build_crypto_binding_response(
            tlv_map[TEAPTLVType.CRYPTO_BINDING], self._cmk
        )

        response_data = (
            tlv.result_tlv(TEAPResultStatus.SUCCESS)
            + tlv.encode_tlv(TEAPTLVType.CRYPTO_BINDING, True, cb_response)
        )
        encrypted = self._outer_tunnel.encrypt(response_data)
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        self._log_msg("→", "TEAP", "Result(Success) + Crypto-Binding(Response)")
        return await self._radius_exchange(resp)

    # ── RADIUS transport ────────────────────────────────────

    async def _send_fragmented(self, data: bytes, max_chunk: int = 1014) -> bytes | None:
        """Send large TEAP data in fragments, waiting for ACK between each."""
        from .types import TEAP_FLAG_M
        total = len(data)
        offset = 0
        first = True
        while offset < total:
            chunk = data[offset:offset + max_chunk]
            is_last = (offset + max_chunk >= total)
            if first:
                resp_pkt = eap.encode_teap_response_with_length(
                    self._eap_id, TEAP_FLAG_M if not is_last else 0, total, chunk
                )
                first = False
            elif is_last:
                resp_pkt = eap.encode_teap_response(self._eap_id, 0, chunk)
            else:
                resp_pkt = eap.encode_teap_response(self._eap_id, TEAP_FLAG_M, chunk)
            offset += max_chunk

            radius_resp = await self._radius_exchange(resp_pkt)
            if is_last:
                return radius_resp
            if not radius_resp:
                return self._fail("No ACK for fragment")
            ack_parsed = rad.decode_response(radius_resp, self._secret, self._authenticator)
            self._radius_state = ack_parsed.get("state") or self._radius_state
            ack_eap = ack_parsed.get("eap_message")
            if ack_eap:
                ack_pkt = eap.decode_eap(ack_eap)
                self._eap_id = ack_pkt["id"]
                self._log_msg("←", "DEBUG", f"Fragment ACK, new eap_id={self._eap_id}")
        return None

    async def _radius_exchange(self, eap_message: bytes) -> bytes | None:
        if len(eap_message) >= 2:
            sent_eap_id = eap_message[1]
            self._log_msg("→", "DEBUG", f"Sending EAP response id={sent_eap_id} (len={len(eap_message)})")
        self._authenticator = rad.make_authenticator()
        attrs = build_request_attrs(self.config, eap_message,
                                    outer_identity=self._outer_identity(),
                                    connect_info=self._connect_info(),
                                    radius_state=self._radius_state)

        radius_id = self._next_radius_id()
        packet = rad.encode_request(
            RadiusCode.ACCESS_REQUEST, radius_id,
            self._authenticator, self._secret, attrs
        )
        reply = await rad.send_receive(
            self.config.radius_host, self.config.radius_port,
            self._secret, packet,
            timeout=self.config.exchange_timeout,
            retries=self.config.retries,
            source_ip=self.config.bind_ip,
            expected_id=radius_id,
        )
        self._capture_reply_attrs(reply)
        return reply

    # ── Helpers ─────────────────────────────────────────────

    def _capture_reply_attrs(self, reply: bytes | None) -> None:
        """Record the attributes of the most recent RADIUS reply.

        Called for every reply, including the terminal Access-Accept, which the
        run loop never feeds to _process_response because the state is already
        DONE by then. Class (25) and State (24) are what accounting and CoA
        need later; the rest is the server's authorization result.
        """
        if not reply:
            return
        try:
            parsed = rad.decode_response(reply, self._secret, self._authenticator)
        except ValueError:
            return
        # A repeated type keeps every value: ISE sends each Cisco-AVPair (the
        # dACL among them) and both MS-MPPE keys as separate Vendor-Specific
        # attributes, and keeping only the last one dropped the dACL.
        attrs: dict[int, str | list[str]] = {}
        for number, value in parsed.get("attrs", []):
            if number in attrs:
                prev = attrs[number]
                attrs[number] = (prev if isinstance(prev, list) else [prev]) + [value.hex()]
            else:
                attrs[number] = value.hex()
        self._reply_attrs = attrs
        self._reply_code = parsed.get("code", 0)

    def _outer_identity(self) -> str:
        """Identity sent in the clear, before the tunnel exists.

        The real identities travel inside the tunnel; the outer one is visible
        on the wire, which is why Windows sends 'anonymous' here.
        """
        return self.config.outer_identity or self.config.identity

    def _connect_info(self) -> str:
        """Connect-Info consistent with the advertised NAS-Port-Type."""
        if self.config.connect_info:
            return self.config.connect_info
        return "CONNECT 802.11" if self.config.nas_port_type == 19 else "CONNECT Ethernet"

    def _next_radius_id(self) -> int:
        rid = self._radius_id
        self._radius_id = (self._radius_id + 1) % 256
        return rid

    def _log_msg(self, direction: str, layer: str, message: str):
        elapsed = time.monotonic() - self._start_time if self._start_time else 0
        self._log.append(LogEntry(elapsed, direction, layer, message))

    def _format_log(self) -> str:
        lines = []
        for entry in self._log:
            lines.append(f"[{entry.timestamp:06.3f}] {entry.direction} {entry.layer:8s} {entry.message}")
        if self.state == State.DONE:
            duration = time.monotonic() - self._start_time
            lines.append(f"\nSUCCESS — TEAP authentication completed in {duration:.3f}s")
        elif self.state == State.FAILED:
            lines.append("\nFAILURE — TEAP authentication failed")
        return "\n".join(lines)

    def _fail(self, message: str) -> None:
        self._log_msg("✗", "ERROR", message)
        self.state = State.FAILED
        return None

    def _make_failure(self, message: str) -> TEAPResult:
        self._log_msg("✗", "ERROR", message)
        duration = time.monotonic() - self._start_time
        return TEAPResult(
            success=False, output=self._format_log(),
            duration=duration, log_entries=list(self._log),
            reply_attrs=dict(self._reply_attrs),
                legs=list(self._legs),
        )

    def timeout_result(self, limit: float) -> TEAPResult:
        """Failure result for an overall timeout enforced by the caller."""
        return self._make_failure(f"Overall timeout of {limit:g}s exceeded")
