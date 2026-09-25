# teap-tester

A standalone TEAP (EAP type 55) client with full **EAP chaining** — a user and
a machine authenticated inside the same TEAP tunnel — for testing RADIUS
authentication. Use it from the command line, or through an optional
[web GUI](#web-gui) that runs sessions in bulk and adds accounting and CoA.

It is a plain RFC 7170 implementation with no vendor-specific code paths, so it
targets any RADIUS server that speaks TEAP.

Pure Python; the CLI depends only on `pyOpenSSL` and `cryptography`.
Certificates and keys are read from PEM files.

## Scope

- **Inner methods: EAP-TLS or MS-CHAPv2**, chosen per identity: a leg with a
  certificate runs EAP-TLS, a leg with a password runs MS-CHAPv2. Any other
  method the server proposes is NAK'd toward the configured one. Basic-Password
  is not supported.
- **TLS 1.2 only**, as RFC 7170 specifies. TEAP over TLS 1.3 is a later,
  separate specification and is not implemented.
- Interop is verified against **Cisco ISE**; other TEAP servers should work from
  the spec, but are untested.

## Requirements

- Python 3.11+
- `pyOpenSSL` 24.3+ and `cryptography` 43+ — the only runtime dependencies

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

Exit code is `0` on Access-Accept, `1` on failure — scriptable. On success it
also prints which inner method ran for each identity, whether the server
accepted the Crypto-Binding, and what the Access-Accept granted (VLAN, dACL…).

### EAP chaining

Chaining is automatic: give credentials for **both** a user and a machine, and
the client runs both inner methods with the RFC 7170 Crypto-Binding chain,
matching a Windows supplicant. Give credentials for just one to test a single
identity.

Each identity uses a certificate (EAP-TLS) or a password (MS-CHAPv2), so the two
legs can differ. For example, a machine certificate with a user password:

```bash
export USERPW='...'
teap-tester ... \
  --identity alice@lab.local --password-env USERPW \
  --machine-identity host/pc01.lab.local \
  --machine-cert machine.pem --machine-key machine.key
```

Passwords are read only from environment variables, never from the command
line.

Argument rules enforced by the CLI:

- `--client-cert` and `--client-key` must be given together, as must
  `--machine-cert` and `--machine-key`.
- At least one credential is required: a certificate pair or a password, for
  the user or the machine.
- `--identity` is required with a client cert or `--password-env`;
  `--machine-identity` is required with a machine cert or
  `--machine-password-env`.

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
| `--outer-identity` | Identity sent in the clear (EAP-Response/Identity and User-Name). Defaults to `--identity`; `anonymous` matches the Windows supplicant |
| `--machine-identity` | Machine identity, e.g. `host/pc.lab` |
| `--client-cert` / `--client-key` | User EAP-TLS PEM files |
| `--machine-cert` / `--machine-key` | Machine EAP-TLS PEM files |
| `--password-env VAR` / `--machine-password-env VAR` | User / machine password from this environment variable; selects MS-CHAPv2 for that leg |
| `--ca-chain` | CA bundle that validates the RADIUS server's certificate. Omit it and the server is **not** verified (the tool warns on stderr) |
| `--source-ip` | NAS-IP-Address to advertise. Free-form: it need not be an address on this machine |
| `--bind-ip` | Local address to send from. Must exist on this machine; only needed to choose between interfaces |
| `--timeout` | Overall test timeout, abandons the run (default 30s) |
| `--exchange-timeout` | Per-RADIUS-exchange timeout (default 10s) |
| `--retries` | Attempts per RADIUS exchange before giving up (default 3) |
| `--json` | Machine-readable result (`success`, `duration`, `log`, `authorization`, `legs`, `output`) |
| `-v/--verbose` | Print the step-by-step timeline |
| `-q/--quiet` | Print only `SUCCESS` / `FAILURE` |
| `--version` | Print the version and exit |

## Layout

```
teap_tester/               the protocol client, no web dependencies
├── cli.py                 argparse CLI
├── __init__.py            run_teap_test() wrapper
├── types.py               enums, config, result dataclasses
├── tlv.py                 TEAP TLV encode/decode
├── eap.py                 EAP packet parsing
├── radius.py              RADIUS packet build/parse, reply validation
├── crypto_binding.py      RFC 7170 Crypto-Binding
├── mschapv2.py            RFC 2759, with MD4 and DES supplied here
├── accounting.py          RFC 2866 Start/Interim/Stop
├── coa.py                 RFC 5176 CoA and Disconnect
├── authorization.py       decode what an Access-Accept granted
├── tunnel.py              pyOpenSSL memory-BIO TLS tunnel
├── inner_tls.py           inner EAP-TLS, run inside the tunnel
├── inner_mschapv2.py      inner EAP-MSCHAPv2, run inside the tunnel
└── state_machine.py       TEAPSession — the state machine

teap_gui/                  the web front end; imports teap_tester, never the reverse
├── app.py                 FastAPI routes
├── origin.py              refuses form posts from other sites
├── db.py                  engine and session factory
├── migrate.py             applies Alembic migrations at startup
├── migrations/            Alembic environment and versions
├── models.py              SQLAlchemy schema
├── generator.py           job runner and per-session execution
├── bulk.py                actions across a whole filter
├── coa_listener.py        udp/3799 listener
├── interim.py             periodic Interim-Update timer
├── expiry.py              session lifetime and termination action
├── certs.py               certificate parsing and identity derivation
├── template.py            per-session value templates
├── secrets.py             encryption at rest
└── templates/, static/    Jinja2 pages and the stylesheet
```

## Web GUI

A browser front end for the same client: stored servers and certificates,
session generation in bulk, accounting, CoA, and a per-session view of what ran
inside the tunnel and what the server granted.

| Page | What it is for |
|---|---|
| Generate | Build and run a job: network access device, server, how many sessions, MAC and IP strategies, TEAP parameters, compiled attributes |
| Sessions | What was generated, with the exchange timeline, inner methods, and the authorization decoded from the Access-Accept |
| Jobs | Progress and outcome of each run |
| Certificates | Trusted chains that validate the server, and identity certificates presented by the client |
| Servers | RADIUS servers; shared secrets encrypted at rest |
| Wiki | What TEAP is, which certificate goes where, every field explained, and common failures |

### Run it directly

```bash
pip install -e '.[gui]'
uvicorn teap_gui.app:app --port 8010
```

Then open <http://127.0.0.1:8010>. Add `--reload` while developing so edits are
picked up without a restart.

### Run it in a container

Built and verified with nerdctl/buildkit on linux/arm64 — 254 MB, runs as an
unprivileged user, and the data volume carries the database, certificates and
encryption key across restarts. The image is plain OCI, so Docker, podman and
nerdctl all work and podman needs nothing special, rootless included.

```bash
docker compose up --build            # or: podman compose up --build

# or without compose
podman build -t teap-tester .
podman run -d --name teap -p 127.0.0.1:8010:8010 -v teap-data:/data teap-tester
```

### Exposing it beyond localhost

Compose binds to `127.0.0.1` by default. To reach it from a VM or a lab jump
host, set the address:

```bash
TEAP_GUI_BIND=0.0.0.0 docker compose up -d      # every interface
TEAP_GUI_BIND=10.0.0.5 docker compose up -d     # one interface
```

Or copy `.env.example` to `.env` and edit it there. Everything in it has a safe
default, so an empty `.env` behaves the same as none.

| Variable | Default | |
|---|---|---|
| `TEAP_GUI_BIND` | `127.0.0.1` | Host address the web interface listens on |
| `TEAP_GUI_PORT` | `8010` | Host port |
| `TEAP_COA_BIND` | `0.0.0.0` | Host address for CoA, if you uncomment that mapping |
| `TEAP_COA_PORT` | `3799` | Host port for CoA |

The app has **no authentication of its own** and holds private keys and RADIUS
shared secrets, so anything beyond localhost should be a network you trust. Put
it behind a reverse proxy that authenticates if it needs to be reachable more
widely. If that proxy rewrites the `Host` header, set `TEAP_GUI_ALLOWED_ORIGINS`
to its public origin — see [Configuration](#configuration).

Form posts from another site's page are refused, so a page open in the same
browser cannot start jobs or delete data here. That is not authentication: any
client that can reach the port and sends no `Origin` header, curl included, is
served.

Bind-mounting a host directory instead of a named volume on SELinux (Fedora,
RHEL) needs `:Z` — `-v ./data:/data:Z`.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TEAP_GUI_DATA` | `./data` (`/data` in the image) | Database, uploaded certificates and the encryption key |
| `TEAP_GUI_KEY` | generated on first run | Fernet key encrypting shared secrets and private keys. Set it explicitly to keep stored secrets readable across a recreated volume |
| `DATABASE_URL` | SQLite in the data directory | Any SQLAlchemy URL, if SQLite stops being enough |
| `TEAP_GUI_COA_PORT` | 3799 | Where to listen for Change-of-Authorization |
| `TEAP_GUI_ALLOWED_ORIGINS` | none | Public origin(s) behind a reverse proxy that rewrites `Host`, e.g. `https://teap.lab.example`. Form posts from any other site are refused |

The data directory is the thing to protect: anyone who can read it can read
every stored secret. The generated key file is written `0600`.

### Database upgrades

The schema is managed with Alembic and upgraded automatically at startup, so a
new release runs against an existing data directory without any manual step.
A data directory from before migrations were introduced upgrades in place too.

Changing a model needs a migration to go with it — a test fails until there is
one:

```bash
TEAP_GUI_DATA=./data alembic -c teap_gui/alembic.ini upgrade head
TEAP_GUI_DATA=./data alembic -c teap_gui/alembic.ini revision --autogenerate -m "what changed"
```

Review the generated file under `teap_gui/migrations/versions/` before
committing it: autogenerate misses renames and anything it cannot see in the
models.

### Receiving CoA

The listener binds udp/3799 at startup. It has to be reachable from the policy
server, so unlike the web port it cannot be bound to localhost — uncomment the
`3799:3799/udp` line in `docker-compose.yml`.

A request is accepted only if it is signed with a shared secret belonging to one
of your configured servers, whatever address it arrives from; one that is not is
silently discarded, as RFC 5176 requires.

A job or bulk action still running when the app stops is marked
`interrupted` on the next start; it can then be deleted and re-run.

### First run

1. **Servers** — add the RADIUS server and its shared secret.
2. **Certificates** — upload the chain that validates the *server's* EAP
   certificate under Trusted, and your client certificates under Identity. These
   are usually different PKIs; using your own issuer as the trusted chain is the
   most common mistake.
3. **Generate** — pick the server, choose an inner method per leg, and run one
   session before running five hundred.

An empty Authorization column on a session means the server granted nothing
beyond the accept — worth noticing when a policy was meant to push a VLAN or a
dACL.

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
