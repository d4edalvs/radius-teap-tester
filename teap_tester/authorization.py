"""Decode the authorization a server returns in its Access-Accept.

'Accepted' is only half the answer when testing policy; the other half is
which authorization was applied. Everything here is derived from attributes
already captured, so it needs no extra exchange.
"""

from __future__ import annotations

import struct

from .types import RadiusAttr

VENDORS = {
    9: "Cisco",
    311: "Microsoft",
    14179: "Airespace",
    25506: "HPE",
    14823: "Aruba",
}

# Vendor sub-attributes worth naming.
VENDOR_ATTRS = {
    (9, 1): "Cisco-AVPair",
    (9, 2): "Cisco-NAS-Port",
    (311, 16): "MS-MPPE-Send-Key",
    (311, 17): "MS-MPPE-Recv-Key",
    (311, 7): "MS-Primary-DNS-Server",
    (14179, 1): "Airespace-Wlan-Id",
    (14179, 3): "Airespace-Interface-Name",
    (14179, 4): "Airespace-ACL-Name",
}

TUNNEL_TYPES = {13: "VLAN"}
TUNNEL_MEDIA = {6: "802"}
TERMINATION_ACTIONS = {0: "Default (terminate)", 1: "RADIUS-Request (re-authenticate)"}


def _get(attrs: dict, number: int) -> str | None:
    """Attributes arrive keyed by int live and by string from storage."""
    if not attrs:
        return None
    return attrs.get(number) or attrs.get(str(int(number)))


def _text(raw: bytes) -> str:
    try:
        text = raw.decode()
        return text if text.isprintable() else "0x" + raw.hex()
    except UnicodeDecodeError:
        return "0x" + raw.hex()


def _tagged(raw: bytes) -> bytes:
    """Strip a tag octet from a tunnel attribute (RFC 2868 section 3.1).

    A leading octet of 0x00-0x1F is a tag rather than data.
    """
    if raw and raw[0] <= 0x1F:
        return raw[1:]
    return raw


def parse_vsa(value: bytes) -> tuple[int, list[tuple[int, bytes]]]:
    """Split a Vendor-Specific attribute into its vendor and sub-attributes."""
    if len(value) < 4:
        return 0, []
    vendor = struct.unpack("!I", value[:4])[0]
    out, offset = [], 4
    while offset + 2 <= len(value):
        subtype, length = value[offset], value[offset + 1]
        if length < 2 or offset + length > len(value):
            break
        out.append((subtype, value[offset + 2:offset + length]))
        offset += length
    return vendor, out


def parse_avpair(text: str) -> tuple[str, str]:
    """Split a Cisco AVPair into name and value.

    ISE prefixes some with a scope, e.g.
    'ACS:CiscoSecure-Defined-ACL=#ACSACL#-IP-PERMIT_ALL'.
    """
    name, _, value = text.partition("=")
    return name.strip(), value.strip()


def decode(attrs: dict) -> dict:
    """Return highlights worth showing first, and every decoded attribute."""
    highlights: dict[str, str] = {}
    items: list[tuple[str, str]] = []

    tunnel_type = _get(attrs, RadiusAttr.TUNNEL_TYPE)
    tunnel_group = _get(attrs, RadiusAttr.TUNNEL_PRIVATE_GROUP_ID)
    if tunnel_group:
        vlan = _text(_tagged(bytes.fromhex(tunnel_group)))
        if tunnel_type:
            code = int.from_bytes(_tagged(bytes.fromhex(tunnel_type)), "big")
            if TUNNEL_TYPES.get(code) == "VLAN":
                highlights["VLAN"] = vlan
        items.append(("Tunnel-Private-Group-ID", vlan))

    for number, label in ((RadiusAttr.FILTER_ID, "Filter-Id"),
                          (RadiusAttr.REPLY_MESSAGE, "Reply-Message")):
        raw = _get(attrs, number)
        if raw:
            value = _text(bytes.fromhex(raw))
            items.append((label, value))
            highlights.setdefault(label, value)

    framed = _get(attrs, RadiusAttr.FRAMED_IP_ADDRESS)
    if framed:
        data = bytes.fromhex(framed)
        if len(data) == 4:
            items.append(("Framed-IP-Address", ".".join(str(b) for b in data)))

    for number, label in ((RadiusAttr.SESSION_TIMEOUT, "Session-Timeout"),
                          (RadiusAttr.IDLE_TIMEOUT, "Idle-Timeout")):
        raw = _get(attrs, number)
        if raw:
            seconds = int(raw, 16)
            items.append((label, f"{seconds} s"))
            highlights[label] = f"{seconds} s"

    action = _get(attrs, RadiusAttr.TERMINATION_ACTION)
    if action:
        code = int(action, 16)
        items.append(("Termination-Action",
                      TERMINATION_ACTIONS.get(code, str(code))))

    klass = _get(attrs, RadiusAttr.CLASS)
    if klass:
        items.append(("Class", _text(bytes.fromhex(klass))))

    vsa = _get(attrs, RadiusAttr.VENDOR_SPECIFIC)
    if vsa:
        vendor, subs = parse_vsa(bytes.fromhex(vsa))
        vendor_name = VENDORS.get(vendor, f"vendor {vendor}")
        for subtype, raw in subs:
            label = VENDOR_ATTRS.get((vendor, subtype),
                                     f"{vendor_name} attribute {subtype}")
            if (vendor, subtype) == (9, 1):
                name, value = parse_avpair(_text(raw))
                items.append((f"Cisco-AVPair {name}", value))
                lowered = name.lower()
                if "defined-acl" in lowered:
                    highlights["dACL"] = value
                elif lowered.endswith("url-redirect"):
                    highlights["URL redirect"] = value
                elif "vlan" in lowered:
                    highlights.setdefault("VLAN", value)
            elif subtype in (16, 17) and vendor == 311:
                # RFC 2548: encrypted with the shared secret and the request
                # authenticator, neither of which survives into storage.
                items.append((label, f"encrypted, {len(raw)} octets"))
            else:
                items.append((label, _text(raw)))

    return {"highlights": highlights, "items": items}
