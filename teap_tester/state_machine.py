"""TEAP session orchestrator — the main protocol loop."""

from __future__ import annotations

import hmac
import socket
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
    TEAPErrorCode,
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
    FLAG_EMSK,
    FLAG_MSK,
    build_crypto_binding_response,
    compound_mac,
    compute_imck,
    parse_crypto_binding,
    request_problem,
    tls_prf,
)


class BindingError(Exception):
    """A Crypto-Binding request that fails validation: a fatal tunnel error."""


# TLVs this peer understands inside the tunnel. Any other TLV marked mandatory
# is answered with a NAK (RFC 9930 section 4.3).
SUPPORTED_TLVS = frozenset({
    TEAPTLVType.IDENTITY_TYPE, TEAPTLVType.RESULT, TEAPTLVType.NAK,
    TEAPTLVType.ERROR, TEAPTLVType.EAP_PAYLOAD, TEAPTLVType.INTERMEDIATE_RESULT,
    TEAPTLVType.PAC, TEAPTLVType.CRYPTO_BINDING,
})


def default_nas_ip(radius_host: str, radius_port: int = 1812, bind_ip: str = "") -> str:
    """The local address this machine reaches the RADIUS server from.

    Used as NAS-IP-Address when none is configured. Resolving our own hostname
    fails on many Macs, whose .local name has no DNS entry; asking the routing
    table which source address reaches the server needs no DNS for an IP
    server, and connecting a UDP socket sends no packet.
    """
    if bind_ip:
        return bind_ip
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((radius_host, radius_port or 1812))
            return probe.getsockname()[0]
    except OSError:
        return "0.0.0.0"


def build_request_attrs(config, eap_message: bytes = b"", *,
                        outer_identity: str = "", connect_info: str = "",
                        radius_state: bytes | None = None
                        ) -> list[tuple[int, bytes]]:
    """Attributes carried by an Access-Request.

    Shared with anything that needs to show what will be sent before sending
    it; a separate implementation would drift from the real one.
    """
    nas_ip = config.source_ip or default_nas_ip(config.radius_host, config.radius_port,
                                                 config.bind_ip)
    try:
        nas_ip_bytes = socket.inet_aton(nas_ip)
    except OSError:
        nas_ip_bytes = socket.inet_aton("0.0.0.0")

    attrs: list[tuple[int, bytes]] = [
        (RadiusAttr.USER_NAME, (outer_identity or config.identity
                                or config.machine_identity).encode()),
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
        # Inner methods whose keys have entered the S-IMCK chains, and whether
        # the final Result has been acknowledged: EAP-Success before that is
        # refused (RFC 9930 section 3.6.6).
        self._binding_rounds = 0
        self._result_acknowledged = False
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
            return self._make_failure(f"Timeout: {e}" + self._silence_hint())
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
                    return self._accept_success()
            self._log_msg("←", "RADIUS", "Access-Accept")
            return self._accept_success()

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
            return self._accept_success()

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

            # RFC 9930 lets the server put its first TLVs in the flight that
            # finishes the handshake (hostapd does); answer them rather than ACK.
            if not outgoing:
                early = self._outer_tunnel.read_pending()
                if early:
                    return await self._dispatch_tlvs(tlv.decode_tlvs(early))

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

        # Section 4.3: a mandatory TLV this peer does not support is NAKed and
        # the rest of the message ignored, except alongside a Result TLV,
        # where a NAK is not allowed (section 4.2.5).
        unsupported = [(t, v) for t, mandatory, v in tlvs
                       if mandatory and t not in SUPPORTED_TLVS]
        if unsupported:
            names = ", ".join(str(t) for t, _v in unsupported)
            if TEAPTLVType.RESULT in tlv_types:
                return await self._fatal(TEAPErrorCode.UNEXPECTED_TLVS_EXCHANGED,
                                         f"Unsupported mandatory TLV(s) with a Result: {names}")
            self._log_msg("←", "TEAP", f"Unsupported mandatory TLV(s): {names}")
            naks = b"".join(
                tlv.nak_tlv(t, struct.unpack("!I", v[:4])[0]
                            if t == TEAPTLVType.VENDOR_SPECIFIC and len(v) >= 4 else 0)
                for t, v in unsupported)
            encrypted = self._outer_tunnel.encrypt(naks)
            resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
            self._log_msg("→", "TEAP", f"NAK({names})")
            return await self._radius_exchange(resp)

        # Result + PAC TLV: acknowledge it; a final Result follows
        if TEAPTLVType.RESULT in tlv_types and TEAPTLVType.PAC in tlv_types:
            return await self._handle_result_pac(tlv_map)

        # Intermediate-Result + Result + Crypto-Binding: the last inner method's
        # binding and the final result in one message (hostapd). Checked first:
        # it satisfies both narrower conditions below.
        if {TEAPTLVType.INTERMEDIATE_RESULT, TEAPTLVType.RESULT,
                TEAPTLVType.CRYPTO_BINDING} <= tlv_types:
            return await self._handle_last_binding_and_result(tlv_map)

        # Result + Crypto-Binding → final handshake
        if TEAPTLVType.RESULT in tlv_types and TEAPTLVType.CRYPTO_BINDING in tlv_types:
            return await self._handle_final_result(tlv_map)

        # Intermediate-Result + Crypto-Binding. Must precede the Crypto-Binding
        # test below: the broader condition would otherwise shadow this one and
        # an Intermediate-Result(Failure) would be silently ignored.
        if TEAPTLVType.INTERMEDIATE_RESULT in tlv_types and TEAPTLVType.CRYPTO_BINDING in tlv_types:
            return await self._handle_intermediate_result_crypto(tlv_map)

        # Intermediate-Result without a binding (section 4.2.11): a failed inner
        # method, usually with an Error TLV saying why. Acknowledged with our
        # own Intermediate-Result; the server then tries another method or
        # ends with a Result. A success always comes with a Crypto-Binding.
        if (TEAPTLVType.INTERMEDIATE_RESULT in tlv_types
                and TEAPTLVType.CRYPTO_BINDING not in tlv_types
                and TEAPTLVType.RESULT not in tlv_types):
            return await self._handle_intermediate_failure(tlv_map)

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
            if result_val != TEAPResultStatus.SUCCESS:
                self._log_msg("←", "TEAP", "Result(Failure)")
                return await self._answer_failure()
            self._log_msg("←", "TEAP", "Result(Success)")
            # Section 3.6.6: success is only protected once a Crypto-Binding
            # has been exchanged; without one the result could be forged.
            if not self._crypto_binding_done:
                return await self._fatal(TEAPErrorCode.UNEXPECTED_TLVS_EXCHANGED,
                                         "Result(Success) without any Crypto-Binding")
            # The verdict is the RADIUS reply to this, not the TLV itself.
            self._result_acknowledged = True
            response_data = tlv.result_tlv(TEAPResultStatus.SUCCESS)
            encrypted = self._outer_tunnel.encrypt(response_data)
            resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
            self._log_msg("→", "TEAP", "Result(Success) [final]")
            return await self._radius_exchange(resp)

        type_names = ", ".join(str(t) for t in tlv_types)
        self._log_msg("←", "TEAP", f"Unhandled TLVs: {type_names}")
        resp = eap.encode_teap_response(self._eap_id, 0)
        return await self._radius_exchange(resp)

    # ── Identity-Type handling ──────────────────────────────

    async def _handle_identity_type(self, tlv_map: dict,
                                    extra_response: bytes = b"") -> bytes | None:
        id_type = struct.unpack("!H", tlv_map[TEAPTLVType.IDENTITY_TYPE][:2])[0]
        self._current_identity_type = id_type
        type_name = "Machine" if id_type == TEAPIdentityType.MACHINE else "User"
        self._log_msg("←", "TEAP", f"Identity-Type request: {type_name}")

        if not self._has_credential_for(id_type):
            # RFC 9930 section 4.2.3: answer with an identity type we do have.
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
            offer = extra_response + tlv.identity_type_tlv(other)
            # Section 4.2.3: an Identity-Type TLV from the peer MUST come with
            # an EAP-Payload, so the server's request is answered as the
            # offered identity. Sending the TLV alone is what ISE rejects as
            # "12963 Received malformed EAP Payload TLV".
            if TEAPTLVType.EAP_PAYLOAD in tlv_map:
                return await self._handle_inner_eap(tlv_map, extra_response=offer)
            encrypted = self._outer_tunnel.encrypt(offer)
            resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
            return await self._radius_exchange(resp)
        self.state = State.INNER_IDENTITY
        # Reset inner tunnel for new inner method
        self._inner_tunnel = None

        response_tlv = extra_response + tlv.identity_type_tlv(TEAPIdentityType(id_type))

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

    def _bind(self, cb_value: bytes) -> bytes:
        """Verify the server's Binding Request and build the Binding Response.

        RFC 9930 sections 4.2.13 and 6.2.4: the request's fields are checked,
        the keys of the inner method just completed are derived, and every
        Compound MAC the server sent that this peer can compute must verify
        before anything is answered. Raises BindingError otherwise.
        """
        parsed = parse_crypto_binding(cb_value)
        if "error" in parsed:
            raise BindingError(parsed["error"])
        self._log_msg("←", "TEAP",
                      f"Crypto-Binding request (ver={parsed['version']}, "
                      f"recv_ver={parsed['received_version']}, "
                      f"flags={parsed['flags']}, sub={parsed['sub_type']}, "
                      f"nonce={parsed['nonce'][:8].hex()}...)")
        problem = request_problem(parsed)
        if problem:
            raise BindingError(problem)

        # The PRF and MAC follow the TLS cipher suite (section 6).
        cipher = self._outer_tunnel.get_cipher_name() if self._outer_tunnel else ""
        self._hash_alg = "sha384" if "SHA384" in cipher.upper() else "sha256"

        # One key derivation per inner method. A binding with no inner method
        # run uses the all-zero IMSK (section 6.3); a server repeating the
        # binding for a method already bound reuses its keys.
        if len(self._legs) > self._binding_rounds or self._binding_rounds == 0:
            self._derive_binding_keys()
            self._binding_rounds += 1

        mac_args = (self._hash_alg, self._server_outer_tlvs, b"")
        flags = parsed["flags"]
        if flags & FLAG_MSK and not hmac.compare_digest(
                compound_mac(cb_value, self._cmk, *mac_args), parsed["msk_mac"]):
            raise BindingError("the server's MSK Compound MAC does not verify")
        if flags & FLAG_EMSK and self._emsk_cmk and not hmac.compare_digest(
                compound_mac(cb_value, self._emsk_cmk, *mac_args), parsed["emsk_mac"]):
            raise BindingError("the server's EMSK Compound MAC does not verify")
        verified = " + ".join(name for bit, name, key in (
            (FLAG_EMSK, "EMSK", self._emsk_cmk), (FLAG_MSK, "MSK", self._cmk))
            if flags & bit and key)
        self._log_msg("✓", "TEAP", f"Server Compound MAC verified ({verified})")

        try:
            cb_response = build_crypto_binding_response(
                cb_value, self._cmk, self._hash_alg,
                server_outer_tlvs=self._server_outer_tlvs,
                emsk_cmk=self._emsk_cmk, include_msk=bool(flags & FLAG_MSK))
        except ValueError:
            raise BindingError("the server sent only an EMSK Compound MAC and this "
                               "inner method has no EMSK")
        self._crypto_binding_done = True
        self._bind_current_leg()
        return cb_response

    def _derive_binding_keys(self) -> None:
        """Advance both S-IMCK chains for the inner method just completed.

        Section 6.2: the MSK and EMSK chains are independent. IMSK_MSK is the
        MSK's first 32 octets, zero-padded; IMSK_EMSK comes from the EMSK via
        TLS-PRF. A method with no EMSK leaves the EMSK chain where it was and
        its binding carries no EMSK Compound MAC (section 6.2.5).
        """
        if not self._s_imck:
            self._s_imck = self._session_key_seed[:40]          # S-IMCK[0]
            self._s_imck_emsk = self._session_key_seed[:40]

        imck = compute_imck(self._s_imck, self._inner_msk[:32], self._hash_alg)
        self._s_imck, self._cmk = imck[:40], imck[40:60]

        inner_emsk = b""
        if self._inner_tunnel:
            try:
                inner_emsk = self._inner_tunnel.export_inner_emsk()
            except Exception as e:
                self._log_msg("!", "TEAP", f"Inner EMSK export unavailable ({e}); "
                                           "binding with the MSK Compound MAC only")
        if inner_emsk:
            imsk_emsk = tls_prf(inner_emsk, b"TEAPbindkey@ietf.org",
                                b"\x00\x00\x40", 32, self._hash_alg)
            imck = compute_imck(self._s_imck_emsk, imsk_emsk, self._hash_alg)
            self._s_imck_emsk, self._emsk_cmk = imck[:40], imck[40:60]
        else:
            self._emsk_cmk = b""

    async def _fatal(self, code: int, message: str) -> bytes | None:
        """End Phase 2 with Result(Failure) and an Error TLV (section 3.9.3)."""
        self._log_msg("✗", "TEAP", message)
        self.state = State.FAILED
        encrypted = self._outer_tunnel.encrypt(
            tlv.result_tlv(TEAPResultStatus.FAILURE) + tlv.error_tlv(code))
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        self._log_msg("→", "TEAP", f"Result(Failure) + Error({int(code)})")
        return await self._radius_exchange(resp)

    async def _refuse_binding(self, error: BindingError) -> bytes | None:
        return await self._fatal(TEAPErrorCode.TUNNEL_COMPROMISE,
                                 f"Crypto-Binding rejected: {error}")

    async def _handle_intermediate_failure(self, tlv_map: dict) -> bytes | None:
        status = struct.unpack("!H", tlv_map[TEAPTLVType.INTERMEDIATE_RESULT][:2])[0]
        if status == TEAPResultStatus.SUCCESS:
            return await self._fatal(TEAPErrorCode.UNEXPECTED_TLVS_EXCHANGED,
                                     "Intermediate-Result(Success) without a Crypto-Binding")
        why = ""
        if TEAPTLVType.ERROR in tlv_map and len(tlv_map[TEAPTLVType.ERROR]) >= 4:
            why = f", Error {struct.unpack('!I', tlv_map[TEAPTLVType.ERROR][:4])[0]}"
        self._log_msg("←", "TEAP", f"Intermediate-Result(Failure){why} — the server "
                                   "refused this inner method")
        encrypted = self._outer_tunnel.encrypt(
            tlv.intermediate_result_tlv(TEAPResultStatus.FAILURE))
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        self._log_msg("→", "TEAP", "Intermediate-Result(Failure)")
        return await self._radius_exchange(resp)

    async def _answer_failure(self) -> bytes | None:
        """Acknowledge the server's Result(Failure) with our own (section 3.9.3)."""
        self.state = State.FAILED
        encrypted = self._outer_tunnel.encrypt(tlv.result_tlv(TEAPResultStatus.FAILURE))
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        self._log_msg("→", "TEAP", "Result(Failure)")
        return await self._radius_exchange(resp)

    async def _handle_crypto_binding(self, tlv_map: dict) -> bytes | None:
        try:
            cb_response = self._bind(tlv_map[TEAPTLVType.CRYPTO_BINDING])
        except BindingError as e:
            return await self._refuse_binding(e)
        response_data = (
            tlv.encode_tlv(TEAPTLVType.CRYPTO_BINDING, True, cb_response)
            + tlv.intermediate_result_tlv(TEAPResultStatus.SUCCESS)
        )

        # A server may start the next inner method in the same message as this
        # binding (hostapd does, to save a round trip). Answer both at once:
        # the binding first, then the reply to the next method.
        if TEAPTLVType.IDENTITY_TYPE in tlv_map or TEAPTLVType.EAP_PAYLOAD in tlv_map:
            self._log_msg("→", "TEAP", "Intermediate-Result(Success) + "
                                       "Crypto-Binding(Response), next method follows")
            if TEAPTLVType.IDENTITY_TYPE in tlv_map:
                return await self._handle_identity_type(tlv_map, extra_response=response_data)
            return await self._handle_inner_eap(tlv_map, extra_response=response_data)

        encrypted = self._outer_tunnel.encrypt(response_data)
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        self._log_msg("→", "TEAP", "Intermediate-Result(Success) + Crypto-Binding(Response)")
        self.state = State.CRYPTO_BINDING
        return await self._radius_exchange(resp)

    async def _handle_intermediate_result_crypto(self, tlv_map: dict) -> bytes | None:
        ir_val = struct.unpack("!H", tlv_map[TEAPTLVType.INTERMEDIATE_RESULT][:2])[0]
        status = "Success" if ir_val == TEAPResultStatus.SUCCESS else "Failure"
        self._log_msg("←", "TEAP", f"Intermediate-Result({status}) + Crypto-Binding")

        # Section 4.2.13: a binding accompanies only a successful inner method.
        if ir_val != TEAPResultStatus.SUCCESS:
            return await self._fatal(TEAPErrorCode.UNEXPECTED_TLVS_EXCHANGED,
                                     "Crypto-Binding sent with a failed Intermediate-Result")
        return await self._handle_crypto_binding(tlv_map)

    async def _handle_last_binding_and_result(self, tlv_map: dict) -> bytes | None:
        """Bind the last inner method and accept the final Result together.

        RFC 9930 section 3.6.6: an Intermediate-Result is answered with an
        Intermediate-Result, so the reply carries all three TLVs.
        """
        ir_val = struct.unpack("!H", tlv_map[TEAPTLVType.INTERMEDIATE_RESULT][:2])[0]
        result_val = struct.unpack("!H", tlv_map[TEAPTLVType.RESULT][:2])[0]
        ok = TEAPResultStatus.SUCCESS
        self._log_msg("←", "TEAP",
                      f"Intermediate-Result({'Success' if ir_val == ok else 'Failure'}) + "
                      f"Result({'Success' if result_val == ok else 'Failure'}) + Crypto-Binding")
        # The binding is validated before either result is acted on (4.2.13).
        try:
            cb_response = self._bind(tlv_map[TEAPTLVType.CRYPTO_BINDING])
        except BindingError as e:
            return await self._refuse_binding(e)
        if ir_val != ok or result_val != ok:
            return await self._answer_failure()
        self._result_acknowledged = True
        response_data = (
            tlv.intermediate_result_tlv(TEAPResultStatus.SUCCESS)
            + tlv.encode_tlv(TEAPTLVType.CRYPTO_BINDING, True, cb_response)
            + tlv.result_tlv(TEAPResultStatus.SUCCESS)
        )
        encrypted = self._outer_tunnel.encrypt(response_data)
        resp = eap.encode_teap_response(self._eap_id, 0, encrypted)
        self._log_msg("→", "TEAP",
                      "Intermediate-Result(Success) + Crypto-Binding(Response) + Result(Success)")
        return await self._radius_exchange(resp)

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
            return await self._answer_failure()

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
        """Result + Crypto-Binding: the last binding and the final result together.

        RFC 9930 section 3.6.6. It follows the last inner method, or comes on
        its own when the server runs no inner method, in which case the binding
        uses the all-zero IMSK. The binding is validated before the result is
        read.
        """
        result_val = struct.unpack("!H", tlv_map[TEAPTLVType.RESULT][:2])[0]
        status = "Success" if result_val == TEAPResultStatus.SUCCESS else "Failure"
        self._log_msg("←", "TEAP", f"Result({status}) + Crypto-Binding")
        try:
            cb_response = self._bind(tlv_map[TEAPTLVType.CRYPTO_BINDING])
        except BindingError as e:
            return await self._refuse_binding(e)
        if result_val != TEAPResultStatus.SUCCESS:
            return await self._answer_failure()

        self._result_acknowledged = True
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
        on the wire, which is why Windows sends 'anonymous' here. A
        machine-only run with no outer identity set uses the machine's.
        """
        return (self.config.outer_identity or self.config.identity
                or self.config.machine_identity)

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

    def _accept_success(self) -> None:
        """Take the server's EAP-Success, if the protected result preceded it.

        RFC 9930 section 3.6.6: a peer MUST NOT accept a cleartext EAP-Success
        before the Crypto-Binding and Result exchange. A server that sends one
        early is reported as a failure, which is what a tester should say.
        """
        if not self._result_acknowledged:
            return self._fail("EAP-Success arrived before the protected Result "
                              "exchange (RFC 9930 section 3.6.6)")
        self.state = State.DONE
        return None

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
        return self._make_failure(f"Overall timeout of {limit:g}s exceeded"
                                  + self._silence_hint())

    def _silence_hint(self) -> str:
        """Why a server may never have answered, if it never did."""
        if self._reply_code:
            return ""
        return (" — the server never answered. A RADIUS server silently drops "
                "requests signed with the wrong shared secret, and requests from "
                "an address it has no network device for; check both.")
