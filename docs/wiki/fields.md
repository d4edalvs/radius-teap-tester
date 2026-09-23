# Field reference

Every field on every page, what it does, and what it becomes on the wire.

## Generate → Network Access Device

These describe the switch or access point the request pretends to come from.
Policy servers routinely match on them, so they change *which rule* fires.

| Field | Becomes | Notes |
|---|---|---|
| Source IP | NAS-IP-Address (4) | Must match a configured network device on the server, or the request is dropped before policy. Blank resolves the host's own address. |
| Connection type | NAS-Port-Type (61) | Wired sends 15 (Ethernet), Wireless sends 19 (802.11). A wired/wireless policy split keys off this. |
| Called-Station-Id | Called-Station-Id (30) | The access **device**, not the endpoint — normally the same for every session, since many endpoints share one switch or AP. For wireless, `MAC:SSID`. Omitted entirely if blank. Supports templates, below. |
| MTU | Framed-MTU (12) | Advertised link MTU. Rarely affects policy; affects fragmentation. |
| Timeout | — | Overall wall-clock limit for one session. The run is abandoned past this. |
| Per exchange | — | Limit for a single RADIUS request/response. |
| Retransmit | — | Attempts per exchange before giving up. Worst case is `per exchange × retransmit × number of exchanges`. |

## Generate → Server

Where the Access-Request goes. Either pick a saved server or type one in.

| Field | Notes |
|---|---|
| RADIUS server | Saved servers, managed on the Servers page. |
| Address, Auth port, Acct port | Auth defaults 1812, accounting 1813. |
| Shared secret | Encrypted at rest. A wrong secret fails the Message-Authenticator check and the server discards the request **silently** — indistinguishable from an unreachable server. |

## Generate → Sessions Generation

| Field | Notes |
|---|---|
| Job name | Label for the run. |
| Amount of sessions | How many authentications to perform. |
| Latency between | Milliseconds between session *starts*. Spreads load. |
| Concurrent sessions | How many run at once. Measured throughput peaks around 5 and degrades by 20 — it is not a "more is better" dial. |
| Bulk name | Groups sessions for filtering and for bulk accounting actions later. |
| Start accounting automatically | Sends Accounting-Start after each successful authentication, as a real access device would. A failure to start accounting does not change the authentication result. Combine with the interim timer for a full session lifecycle. |

## Generate → MAC & IP Addresses

| Field | Becomes | Notes |
|---|---|---|
| MAC addresses | Calling-Station-Id (31) | Random generates a unique MAC per session. From list cycles through what you paste. |
| OUI prefix | — | First three octets, e.g. `00-11-22`, to imitate a vendor. Random fills the rest. |
| IP addresses | Framed-IP-Address (8) | Random picks from the CIDR. Blank CIDR sends no address at all. |

## Generate → TEAP Parameters

| Field | Notes |
|---|---|
| Identity mode | **Derived from certificate** reads the identity out of the certificate. **Anonymous** sends `anonymous` in the clear and the real identities inside the tunnel, as the Windows supplicant does. **Manual** uses what you type. |
| User identity | Only in manual mode. Derived mode uses the UPN, else the SAN email, else the Common Name. |
| Machine identity | Only in manual mode. Derived mode uses `host/` plus the SAN DNS name. |
| User / Machine certificate | Select both to exercise EAP chaining. One alone tests a single identity. |
| Trusted certificate | Validates the **server's** certificate. Leave it unset and the server is not verified — the run still succeeds, which is why it is easy to miss. |
| What certificates should be sent | **Full chain**: leaf plus everything stored with it. **Without root**: drops any self-signed certificate, since the server already holds it. **Only identity**: leaf alone, for servers that hold the intermediates. |

## Value templates

Called-Station-Id and any additional attribute value may be a template. These
are rendered **once per session**, so a value referencing the endpoint varies
with it rather than freezing to the first one generated.

| Variable | Is |
|---|---|
| `$MAC$` | this session's Calling-Station-Id |
| `$IP$` | this session's Framed-IP-Address |
| `$SESSION$` | this session's Acct-Session-Id |
| `$INDEX$` | position within the job, starting at 0 |
| `$SSID$` | the configured SSID, if any |

| Function | Does |
|---|---|
| `uc(x)` / `lc(x)` | upper / lower case |
| `hex(x)` | a number as hex, otherwise the bytes as hex |
| `rand(a..b)` | a fresh random integer per session |
| `pad(x,n)` | left-pad with zeros to width n |

Calls nest, innermost first:

    uc(hex(rand(4096..65535)))/uc($MAC$)/uc(hex(rand(4096..65535)))

gives a different value for every session, for example
`ED9C/00-11-22-73-76-1E/8507`. Use this to simulate many access devices; leave
it a plain string to simulate many endpoints behind one device.

The rendered value is stored with each session, so what was actually sent is
visible afterwards on the session detail page.

## Generate → Attributes

Free-text additions, one `TYPE=VALUE` per line. Values are text, or `0x`-prefixed
hex for binary. These are appended to the attributes the panels above produce;
the compiled list shows the complete set that will be sent.

## Sessions

| Column | Meaning |
|---|---|
| Status | `accepted` = Access-Accept, `rejected` = Access-Reject, `timeout` / `error` = no usable answer. |
| Acct | Accounting lifecycle: started, stopped, disconnected, reauthenticated. Independent of the authentication result. |
| Acct-Session-Id | Generated per session and reused for accounting and CoA matching. |
| Duration | Wall-clock time for the authentication. |

Selecting rows enables **Start / Interim / Stop** accounting, **Delete**, and
**Re-authenticate**, which re-runs the full exchange and obtains a new Class.

**Interim updates** can also run on a timer, sending an Interim-Update for every
accounting-started session at the chosen period. The setting survives a restart.
A server that supplies Acct-Interim-Interval (85) overrides the configured value;
ISE does not send it by default, so the configured period is what applies.
Counters are synthetic — this tool generates no user traffic.

## Certificates

| Field | Notes |
|---|---|
| Friendly name | Your label. |
| Type | Trusted validates the server. Identity certificates are presented by the client. |
| Certificate | PEM bundle or PKCS#12. A bundle's extra certificates become the chain. |
| Rename | Only the friendly name and the type can be changed. Subject, issuer, serial and validity come from the file itself; replacing the content means uploading again. |
| Private key | Required for identity certificates. Rejected if it does not match the certificate. |
| PKCS#12 passphrase | Only for `.p12` / `.pfx`. |

## Servers

| Field | Notes |
|---|---|
| Name, Address | Address must match what the server sees as the source of the request. |
| Auth / Acct port | 1812 and 1813 by default. |
| Shared secret | Encrypted at rest, never shown again. |
| CoA enabled | Whether this server is expected to send Change-of-Authorization requests to udp/3799. |
