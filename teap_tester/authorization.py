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
TERMINATION_ACTIONS = {0: "Default", 1: "RADIUS-Request"}


def values(attrs: dict, number: int) -> list[str]:
    """Every value of one attribute, hex-encoded, in the order received.

    Attributes arrive keyed by int live and by string from storage. A type the
    server sent once is a single hex string; one it repeated (Vendor-Specific
    always is: MS-MPPE keys and each Cisco-AVPair) is a list of them.
    """
    if not attrs:
        return []
    raw = attrs.get(number)
    if raw is None:
        raw = attrs.get(str(int(number)))
    if raw is None:
        return []
    return list(raw) if isinstance(raw, list) else [raw]


def first(attrs: dict, number: int) -> str | None:
    """The first value of an attribute, for types that carry one meaning."""
    found = values(attrs, number)
    return found[0] if found else None



def _text(raw: bytes) -> str:
    try:
        text = raw.decode()
        return text if text.isprintable() else "0x" + raw.hex()
    except UnicodeDecodeError:
        return "0x" + raw.hex()


def _tag(raw: bytes) -> tuple[str, bytes]:
    """Split off a tunnel attribute's tag, as '(tag=N) ' for display."""
    if raw and raw[0] <= 0x1F:
        return (f"(tag={raw[0]}) " if raw[0] else ""), raw[1:]
    return "", raw


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
    """Return highlights worth showing first, and every decoded attribute.

    The items follow the layout of ISE's authentication Result, so the two can
    be read side by side: same names, tags shown, keys masked.
    """
    highlights: dict[str, str] = {}
    items: list[tuple[str, str]] = []

    for klass in values(attrs, RadiusAttr.CLASS):
        items.append(("Class", _text(bytes.fromhex(klass))))

    for number, label in ((RadiusAttr.SESSION_TIMEOUT, "Session-Timeout"),
                          (RadiusAttr.IDLE_TIMEOUT, "Idle-Timeout")):
        raw = first(attrs, number)
        if raw:
            seconds = int(raw, 16)
            items.append((label, f"{seconds} seconds"))
            highlights[label] = f"{seconds} s"

    action = first(attrs, RadiusAttr.TERMINATION_ACTION)
    if action:
        code = int(action, 16)
        items.append(("Termination-Action", TERMINATION_ACTIONS.get(code, str(code))))

    for number, label, names in ((RadiusAttr.TUNNEL_TYPE, "Tunnel-Type", TUNNEL_TYPES),
                                 (RadiusAttr.TUNNEL_MEDIUM_TYPE, "Tunnel-Medium-Type",
                                  TUNNEL_MEDIA)):
        for raw in values(attrs, number):
            tag, data = _tag(bytes.fromhex(raw))
            code = int.from_bytes(data, "big")
            items.append((label, tag + names.get(code, str(code))))
    for raw in values(attrs, RadiusAttr.TUNNEL_PRIVATE_GROUP_ID):
        tag, data = _tag(bytes.fromhex(raw))
        items.append(("Tunnel-Private-Group-ID", tag + _text(data)))

    tunnel_type = first(attrs, RadiusAttr.TUNNEL_TYPE)
    tunnel_group = first(attrs, RadiusAttr.TUNNEL_PRIVATE_GROUP_ID)
    if tunnel_group and tunnel_type:
        code = int.from_bytes(_tagged(bytes.fromhex(tunnel_type)), "big")
        if TUNNEL_TYPES.get(code) == "VLAN":
            highlights["VLAN"] = _text(_tagged(bytes.fromhex(tunnel_group)))

    for number, label in ((RadiusAttr.FILTER_ID, "Filter-Id"),
                          (RadiusAttr.REPLY_MESSAGE, "Reply-Message")):
        for raw in values(attrs, number):
            value = _text(bytes.fromhex(raw))
            items.append((label, value))
            highlights.setdefault(label, value)

    framed = first(attrs, RadiusAttr.FRAMED_IP_ADDRESS)
    if framed:
        data = bytes.fromhex(framed)
        if len(data) == 4:
            items.append(("Framed-IP-Address", ".".join(str(b) for b in data)))

    for vsa in values(attrs, RadiusAttr.VENDOR_SPECIFIC):
        vendor, subs = parse_vsa(bytes.fromhex(vsa))
        vendor_name = VENDORS.get(vendor, f"vendor {vendor}")
        for subtype, raw in subs:
            label = VENDOR_ATTRS.get((vendor, subtype),
                                     f"{vendor_name} attribute {subtype}")
            if (vendor, subtype) == (9, 1):
                text = _text(raw)
                items.append(("cisco-av-pair", text))
                name, value = parse_avpair(text)
                lowered = name.lower()
                if "defined-acl" in lowered:
                    highlights["dACL"] = value
                elif lowered.endswith("url-redirect"):
                    highlights["URL redirect"] = value
                elif "vlan" in lowered:
                    highlights.setdefault("VLAN", value)
            elif subtype in (16, 17) and vendor == 311:
                # RFC 2548 MS-MPPE keys: the session's encryption keys for the
                # access device. Masked, as ISE shows them.
                items.append((label, "****"))
            else:
                items.append((label, _text(raw)))

    return {"highlights": highlights, "items": items}
