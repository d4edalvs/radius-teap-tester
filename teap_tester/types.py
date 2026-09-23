"""Constants, enums, and dataclasses for TEAP client."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


# ── RADIUS ──────────────────────────────────────────────────

class RadiusCode(IntEnum):
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCESS_CHALLENGE = 11


class RadiusAttr(IntEnum):
    USER_NAME = 1
    NAS_IP_ADDRESS = 4
    NAS_PORT = 5
    SERVICE_TYPE = 6
    FRAMED_MTU = 12
    STATE = 24
    CALLED_STATION_ID = 30
    CALLING_STATION_ID = 31
    NAS_PORT_TYPE = 61
    NAS_IDENTIFIER = 32
    CONNECT_INFO = 77
    EAP_MESSAGE = 79
    MESSAGE_AUTHENTICATOR = 80


# ── EAP ─────────────────────────────────────────────────────

class EAPCode(IntEnum):
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4


class EAPType(IntEnum):
    IDENTITY = 1
    NAK = 3
    TLS = 13
    TEAP = 55


# ── TEAP TLV ────────────────────────────────────────────────

class TEAPTLVType(IntEnum):
    AUTHORITY_ID = 1
    IDENTITY_TYPE = 2
    RESULT = 3
    NAK = 4
    ERROR = 5
    CHANNEL_BINDING = 6
    VENDOR_SPECIFIC = 7
    REQUEST_ACTION = 8
    EAP_PAYLOAD = 9
    INTERMEDIATE_RESULT = 10
    PAC = 11
    CRYPTO_BINDING = 12


class TEAPResultStatus(IntEnum):
    SUCCESS = 1
    FAILURE = 2


class TEAPIdentityType(IntEnum):
    USER = 1
    MACHINE = 2


# ── TEAP Flags ──────────────────────────────────────────────

TEAP_FLAG_L = 0x80  # Length included
TEAP_FLAG_M = 0x40  # More fragments
TEAP_FLAG_S = 0x20  # Start (outer TLS)
TEAP_VERSION_MASK = 0x07
TEAP_VERSION = 1


# ── PAC TLV sub-types ──────────────────────────────────────

class PACSubType(IntEnum):
    PAC_KEY = 1
    PAC_OPAQUE = 2
    PAC_LIFETIME = 3
    PAC_A_ID = 4
    PAC_I_ID = 5
    PAC_A_ID_INFO = 7
    PAC_ACK = 9
    PAC_TYPE = 10


# ── Dataclasses ─────────────────────────────────────────────

@dataclass
class TEAPTestConfig:
    radius_host: str
    radius_port: int
    radius_secret: str
    identity: str                    # inner (user) identity
    outer_identity: str = ""         # EAP-Response/Identity and User-Name;
                                     # empty reuses identity. 'anonymous' matches
                                     # the Windows supplicant's privacy behaviour.
    machine_identity: str = ""
    client_cert_pem: str = ""
    client_key_pem: str = ""
    machine_cert_pem: str = ""
    machine_key_pem: str = ""
    ca_chain_pem: str = ""
    source_ip: str = ""
    calling_station_id: str = "AA-BB-CC-DD-EE-FF"
    called_station_id: str = ""      # omitted from the request when empty
    nas_port_type: int = 15          # 15 = Ethernet, 19 = Wireless-802.11
    connect_info: str = ""           # derived from nas_port_type when empty
    nas_identifier: str = ""         # omitted from the request when empty
    nas_port: int = 1
    framed_mtu: int = 1500
    retries: int = 3
    extra_attrs: list[tuple[int, bytes]] = field(default_factory=list)
    timeout: float = 30.0          # overall, enforced by run_teap_test()
    exchange_timeout: float = 10.0  # per RADIUS request/response attempt


@dataclass
class LogEntry:
    timestamp: float
    direction: str  # "→" or "←"
    layer: str      # "RADIUS", "TEAP", "EAP"
    message: str


@dataclass
class TEAPResult:
    success: bool
    output: str
    duration: float = 0.0
    log_entries: list[LogEntry] = field(default_factory=list)
    reply_attrs: dict[int, str] = field(default_factory=dict)  # type -> hex
