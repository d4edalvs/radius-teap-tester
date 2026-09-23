# teap-tester

A standalone, CLI-only TEAP (EAP type 55) client with full **EAP chaining** —
user EAP-TLS + machine EAP-TLS inside the TEAP tunnel — for testing RADIUS
authentication from the command line.

It is a plain RFC 7170 implementation with no vendor-specific code paths, so it
targets any RADIUS server that speaks TEAP.

Pure Python (only dependency: `pyOpenSSL`). Certificates and keys are read from
PEM files.

## Scope

- **Inner method: EAP-TLS only.** Any other inner method proposed by the server
  is NAK'd in favour of EAP-TLS. There is no MSCHAPv2 or Basic-Password support.
- **TLS 1.2 only**, as RFC 7170 specifies. TEAP over TLS 1.3 is a later,
  separate specification and is not implemented.
- Interop is verified against **Cisco ISE**; other TEAP servers should work from
  the spec, but are untested.

## Requirements

- Python 3.11+
- `pyOpenSSL` (pulls in `cryptography`) — the only runtime dependency

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
teap-tester --help
```

## Usage

```bash
teap-tester \
  --radius-host 192.0.2.10 \
  --radius-secret-env RSECRET \
  --identity user@lab.local \
  --machine-identity host/pc01.lab.local \
  --client-cert user.pem  --client-key  user.key \
  --machine-cert machine.pem --machine-key machine.key \
  --ca-chain ca-chain.pem \
  --verbose
```

Exit code is `0` on Access-Accept, `1` on failure — scriptable.

### EAP chaining

Chaining is automatic: provide **both** a user identity + client cert **and** a
machine identity + machine cert, and the client runs both inner EAP-TLS methods
with the RFC 7170 Crypto-Binding chain, matching a Windows supplicant. Provide
just one pair to test a single identity.

Argument rules enforced by the CLI:

- `--client-cert` and `--client-key` must be given together, as must
  `--machine-cert` and `--machine-key`.
- At least one of the two pairs is required.
- `--identity` is required with a client cert; `--machine-identity` is required
  with a machine cert.

### Simulating the network access device

ISE and other policy servers routinely match on *how* the request arrives, not
just who is authenticating. These flags shape the RADIUS attributes so a wired
and a wireless request can be told apart:

| Option | Description |
|--------|-------------|
| `--calling-station-id MAC` | Supplicant MAC (default `AA-BB-CC-DD-EE-FF`) |
| `--called-station-id ID` | NAS MAC; for wireless, `MAC:SSID`. Omitted if unset |
| `--nas-port-type N` | `15` = Ethernet (wired 802.1X), `19` = Wireless-802.11 |
| `--nas-identifier ID` | NAS-Identifier string. Omitted if unset |
| `--nas-port` / `--framed-mtu` | Defaults `1` and `1500` |
| `--connect-info S` | Defaults to match `--nas-port-type` |
| `--radius-attr TYPE=VALUE` | Any other attribute, repeatable. Text, or `0x`-prefixed hex |

Wired:

```bash
teap-tester ... --called-station-id 00-11-22-33-44-55
```

Wireless — `--nas-port-type 19` also switches Connect-Info to `CONNECT 802.11`:

```bash
teap-tester ... --nas-port-type 19 \
  --called-station-id 00-11-22-33-44-55:corp-wifi \
  --calling-station-id DE-AD-BE-EF-00-01
```

### Key options

| Option | Description |
|--------|-------------|
| `--radius-host` / `--radius-port` | RADIUS server (port default 1812) |
| `--radius-secret` / `--radius-secret-env VAR` | Shared secret (prefer the env form) |
| `--identity` | User identity / UPN |
| `--machine-identity` | Machine identity, e.g. `host/pc.lab` |
| `--client-cert` / `--client-key` | User EAP-TLS PEM files |
| `--machine-cert` / `--machine-key` | Machine EAP-TLS PEM files |
| `--ca-chain` | CA bundle that validates the RADIUS server's certificate. Omit it and the server is **not** verified (the tool warns on stderr) |
| `--source-ip` | NAS-IP-Address to advertise |
| `--timeout` | Overall test timeout, abandons the run (default 30s) |
| `--exchange-timeout` | Per-RADIUS-exchange timeout, 3 attempts each (default 10s) |
| `--json` | Machine-readable result (`success`, `duration`, `log`, `output`) |
| `-v/--verbose` | Print the step-by-step timeline |
| `-q/--quiet` | Print only `SUCCESS` / `FAILURE` |
| `--version` | Print the version and exit |

## Layout

```
teap_tester/
├── cli.py            # argparse CLI (this repo's only bespoke code)
├── __init__.py       # run_teap_test() wrapper
├── types.py          # enums, config, result dataclasses
├── tlv.py            # TEAP TLV encode/decode
├── eap.py            # EAP packet parsing
├── radius.py         # RADIUS packet build/parse
├── crypto_binding.py # RFC 7170 Crypto-Binding
├── tunnel.py         # pyOpenSSL memory-BIO TLS tunnel
└── state_machine.py  # TEAPSession — the state machine
```

## Web GUI

A browser front end for generating sessions in bulk, storing servers and
certificates, and driving accounting and CoA lives in `teap_gui/`.

```bash
pip install -e '.[gui]'
uvicorn teap_gui.app:app --port 8010
```

### Container

The image works with Docker or podman; podman needs no changes, rootless
included.

```bash
docker compose up --build          # or: podman compose up --build
podman build -t teap-tester .      # plain podman, no compose
podman run --rm -p 127.0.0.1:8010:8010 -v teap-data:/data teap-tester
```

Data lives in the `teap-data` volume: the SQLite database, uploaded
certificates, and the key that encrypts stored secrets. Protect it accordingly,
and set `TEAP_GUI_KEY` if you want stored secrets to survive recreating it.

If you bind-mount a host directory instead of using a named volume on a
SELinux system (Fedora, RHEL), add `:Z` — `-v ./data:/data:Z`.

## Security notes

- Prefer `--radius-secret-env VAR` over `--radius-secret`: the latter puts the
  shared secret in your shell history and in the process list (`ps`), where any
  local user can read it.
- The shared secret and private keys are never written to the step timeline or
  the `--json` output. Identities, the RADIUS host and byte counts **are** —
  treat captured logs from a production RADIUS server accordingly.
- `--ca-chain` is the **server** trust anchor, not your client's issuer. Those are
  often different PKIs: the client cert can be issued by one CA while the RADIUS
  server presents another. Pass the chain that signs the server's EAP certificate.
- Responses are validated: the RADIUS Response Authenticator (RFC 2865 §3) and
  Message-Authenticator (RFC 3579 §3.2) are checked on every reply, and replies
  whose Identifier doesn't match the request are ignored. A wrong shared secret
  fails loudly rather than silently.
- Keep client keys out of the repo. Anything under a `certs/` directory should
  be gitignored and mode `0600`.
- This is a test client. It authenticates *to* a RADIUS server you control (or
  are authorized to test); it is not a supplicant for production use.

## License

MIT — see [LICENSE](LICENSE).
