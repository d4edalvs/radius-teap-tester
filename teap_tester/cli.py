"""Command-line interface for teap-tester.

Runs a TEAP (EAP type 55) authentication against a RADIUS server with optional
EAP chaining (user EAP-TLS + machine EAP-TLS inside the TEAP tunnel).
Certificates and keys are read from PEM files on disk.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from . import __version__, run_teap_test
from . import radius


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="teap-tester",
        description="CLI TEAP (EAP type 55) client with EAP chaining for RADIUS testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    radius = p.add_argument_group("RADIUS")
    radius.add_argument("--radius-host", required=True, help="RADIUS server IP/hostname")
    radius.add_argument("--radius-port", type=int, default=1812, help="RADIUS auth port")
    radius.add_argument("--radius-secret", help="RADIUS shared secret (prefer --radius-secret-env)")
    radius.add_argument("--radius-secret-env", metavar="VAR",
                        help="Read the RADIUS shared secret from this environment variable")

    ident = p.add_argument_group("Identities")
    ident.add_argument("--identity", default="", help="User identity / UPN (user EAP-TLS leg)")
    ident.add_argument("--machine-identity", default="",
                       help="Machine identity, e.g. host/pc.lab (enables the machine leg of EAP chaining)")

    certs = p.add_argument_group("Certificates (PEM files)")
    certs.add_argument("--client-cert", help="User client certificate PEM")
    certs.add_argument("--client-key", help="User client private key PEM")
    certs.add_argument("--machine-cert", help="Machine client certificate PEM")
    certs.add_argument("--machine-key", help="Machine client private key PEM")
    certs.add_argument("--ca-chain", help="CA bundle PEM to validate the server certificate")

    net = p.add_argument_group("Network / timing")
    net.add_argument("--source-ip", default="", help="NAS-IP-Address to advertise")
    nad = p.add_argument_group("NAS / network access device identity")
    nad.add_argument("--calling-station-id", default="AA-BB-CC-DD-EE-FF", metavar="MAC",
                     help="Supplicant MAC (RFC 3580: upper-case hex, dash-separated)")
    nad.add_argument("--called-station-id", default="", metavar="ID",
                     help="NAS MAC; for wireless use MAC:SSID (e.g. "
                          "00-11-22-33-44-55:corp-wifi). Omitted if unset")
    nad.add_argument("--nas-port-type", type=int, default=15, metavar="N",
                     help="RFC 2865 NAS-Port-Type: 15 = Ethernet (wired 802.1X), "
                          "19 = Wireless-802.11 (wireless 802.1X)")
    nad.add_argument("--nas-identifier", default="", metavar="ID",
                     help="NAS-Identifier string. Omitted if unset")
    nad.add_argument("--nas-port", type=int, default=1, metavar="N", help="NAS-Port")
    nad.add_argument("--framed-mtu", type=int, default=1500, metavar="N", help="Framed-MTU")
    nad.add_argument("--connect-info", default="", metavar="S",
                     help="Connect-Info (default follows --nas-port-type)")
    nad.add_argument("--radius-attr", action="append", default=[], metavar="TYPE=VALUE",
                     help="Extra RADIUS attribute, repeatable. VALUE is text, or "
                          "0x-prefixed hex for binary (e.g. 61=6 or 61=0x00000006)")
    net.add_argument("--timeout", type=float, default=30.0,
                     help="Overall test timeout in seconds — the run is abandoned past this")
    net.add_argument("--exchange-timeout", type=float, default=10.0,
                     help="Per-RADIUS-exchange timeout in seconds")
    net.add_argument("--retries", type=int, default=3, metavar="N",
                     help="Attempts per RADIUS exchange before giving up")

    out = p.add_argument_group("Output")
    out.add_argument("--json", action="store_true", help="Emit machine-readable JSON result")
    out.add_argument("-v", "--verbose", action="store_true", help="Print the step-by-step timeline")
    out.add_argument("-q", "--quiet", action="store_true", help="Print only the final verdict")
    return p


def _read_pem(path: str | None, label: str) -> str:
    if not path:
        return ""
    f = Path(path).expanduser()
    if not f.is_file():
        raise SystemExit(f"error: {label} file not found: {path}")
    text = f.read_text()
    if "-----BEGIN" not in text:
        raise SystemExit(f"error: {label} does not look like PEM: {path}")
    return text


def _resolve_secret(args: argparse.Namespace) -> str:
    if args.radius_secret_env:
        val = os.environ.get(args.radius_secret_env)
        if not val:
            raise SystemExit(f"error: environment variable {args.radius_secret_env} is unset or empty")
        return val
    if args.radius_secret:
        return args.radius_secret
    raise SystemExit("error: provide --radius-secret or --radius-secret-env")


def _parse_radius_attrs(specs: list[str]) -> list[tuple[int, bytes]]:
    """Parse repeated --radius-attr TYPE=VALUE into (type, bytes) pairs."""
    out: list[tuple[int, bytes]] = []
    for spec in specs:
        try:
            out.append(radius.parse_attribute_spec(spec))
        except ValueError as exc:
            raise SystemExit(f"error: --radius-attr {exc}")
    return out


def _validate_pairs(args: argparse.Namespace) -> None:
    if bool(args.client_cert) != bool(args.client_key):
        raise SystemExit("error: --client-cert and --client-key must be given together")
    if bool(args.machine_cert) != bool(args.machine_key):
        raise SystemExit("error: --machine-cert and --machine-key must be given together")
    if not args.client_cert and not args.machine_cert:
        raise SystemExit("error: at least one identity required "
                         "(--client-cert/--client-key or --machine-cert/--machine-key)")
    if args.machine_cert and not args.machine_identity:
        raise SystemExit("error: --machine-identity is required when a machine certificate is given")
    if args.client_cert and not args.identity:
        raise SystemExit("error: --identity is required when a client certificate is given")


def _format_entry(e) -> str:
    return f"[{e.timestamp:06.3f}] {e.direction} {e.layer:8s} {e.message}"


def _render_human(result, verbose: bool, quiet: bool) -> None:
    if quiet:
        print("SUCCESS" if result.success else "FAILURE")
        return
    if verbose:
        for e in result.log_entries:
            print(_format_entry(e))
        print()
    elif not result.success:
        # Without -v, still show why it failed.
        for e in result.log_entries:
            if e.direction == "\u2717":
                print(_format_entry(e))
    if result.success:
        print(f"SUCCESS \u2014 TEAP authentication completed in {result.duration:.3f}s")
    else:
        print("FAILURE \u2014 TEAP authentication failed")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _validate_pairs(args)
    secret = _resolve_secret(args)
    if not args.ca_chain:
        print("warning: no --ca-chain given; the server certificate is NOT verified",
              file=sys.stderr)

    kwargs = dict(
        radius_host=args.radius_host,
        radius_port=args.radius_port,
        radius_secret=secret,
        identity=args.identity,
        machine_identity=args.machine_identity,
        client_cert_pem=_read_pem(args.client_cert, "--client-cert"),
        client_key_pem=_read_pem(args.client_key, "--client-key"),
        machine_cert_pem=_read_pem(args.machine_cert, "--machine-cert"),
        machine_key_pem=_read_pem(args.machine_key, "--machine-key"),
        ca_chain_pem=_read_pem(args.ca_chain, "--ca-chain"),
        source_ip=args.source_ip,
        calling_station_id=args.calling_station_id,
        called_station_id=args.called_station_id,
        nas_port_type=args.nas_port_type,
        connect_info=args.connect_info,
        nas_identifier=args.nas_identifier,
        nas_port=args.nas_port,
        framed_mtu=args.framed_mtu,
        extra_attrs=_parse_radius_attrs(args.radius_attr),
        timeout=args.timeout,
        exchange_timeout=args.exchange_timeout,
        retries=args.retries,
    )

    try:
        result = asyncio.run(run_teap_test(**kwargs))
    except KeyboardInterrupt:
        print("aborted", file=sys.stderr)
        return 130

    if args.json:
        print(json.dumps({
            "success": result.success,
            "duration": result.duration,
            "log": [{"time": round(e.timestamp, 3), "direction": e.direction,
                      "layer": e.layer, "message": e.message}
                     for e in result.log_entries],
            "output": result.output,
        }, indent=2))
    else:
        _render_human(result, args.verbose, args.quiet)

    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
