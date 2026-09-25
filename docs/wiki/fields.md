# Field reference

Every control in the interface: what it is, what it becomes on the wire, and
what goes wrong when it is set badly.

Attribute numbers in brackets are RADIUS attribute types, so you can find them
in a packet capture or in a server's own logs.

---

## Generate — Network Access Device

These describe the switch or access point the request pretends to come from. A
policy server decides *which rule applies* largely from these, so they change
the outcome as much as the credential does.

### Source IP → NAS-IP-Address (4)

What the request claims to come from.

**It does not have to be an address on this machine.** That is the point: a
policy server matches its device definition by address, so a test client
routinely claims an address it does not own. If you leave it blank, the address
this machine uses to reach the server is sent, and recorded with the session so
its accounting advertises the same one.

Getting this wrong is silent and total: a server with no device definition for
the address discards the request before policy runs, so you see a timeout and no
log entry at all on the server. If a run times out, this is the first thing to
check.

This is separate from which local interface the packet leaves by — the CLI has
`--bind-ip` for that, and it is almost never needed.

### Connection type → NAS-Port-Type (61)

**Wired** sends 15 (Ethernet), **Wireless** sends 19 (802.11).

A policy set with separate wired and wireless rules keys off exactly this. If a
wireless policy is not matching, confirm this before looking anywhere else.

Choosing Wireless also changes Connect-Info to `CONNECT 802.11`, so the request
is internally consistent rather than claiming to be wireless while describing an
Ethernet connection.

### Called-Station-Id (30)

Identifies the **access device**, not the endpoint — so it is normally the same
for every session, since many endpoints share one switch or access point.

For wireless it carries the SSID after a colon:
`00-11-22-33-44-55:corp-wifi`. SSID-based rules read the part after the colon,
so the separator matters.

Omitted entirely when blank, which is fine unless a rule depends on it.

Supports [value templates](#value-templates), which is how you simulate many
access devices rather than many endpoints behind one.

### NAS-Identifier (32)

A name for the device, as an alternative to identifying it by address. Some
deployments look the device up by this instead. Omitted when blank.

### MTU → Framed-MTU (12)

The link MTU being advertised. Rarely changes policy; it describes what the
access device could carry.

### Timeout, Per exchange, Retransmit

Three different limits, often confused:

| Field | Limits |
|---|---|
| Timeout | the whole session, wall clock. The run is abandoned past this |
| Per exchange | one RADIUS request and its reply |
| Retransmit | attempts per exchange before giving up |

Worst case is roughly `per exchange × retransmit × number of exchanges`, and a
chained authentication makes around fifty exchanges. That is why the overall
timeout exists: without it, a server that stalls rather than refusing could hold
a run open for an hour.

---

## Generate — Server

Where the Access-Request goes.

**Load server info** picks a server saved on the Servers page. **Enter directly**
takes an address, ports and secret for a one-off; tick *keep* to save it,
otherwise it is recorded as ad-hoc so accounting and CoA can still resolve its
secret later.

The shared secret is encrypted at rest and never rendered back to the page.

A wrong secret does not produce an error. The server cannot validate the
Message-Authenticator, so it **discards the packet in silence** and the run
times out looking exactly like an unreachable host. If a previously working
server starts timing out, suspect the secret before the network.

---

## Generate — Sessions Generation

| Field | Notes |
|---|---|
| Job name | A label for the run; it appears on the Jobs page |
| Amount of sessions | How many authentications to perform |
| Latency between | Milliseconds between session *starts*, to spread load rather than arriving all at once |
| Concurrent sessions | How many run at the same time |
| Bulk name | Groups sessions so you can filter and act on them together afterwards |
| Session lifetime | Seconds before the session expires. 0 means never |
| At expiry | Re-authenticate, or terminate with an Accounting-Stop |
| Start accounting automatically | Send Accounting-Start after each success, as a real access device does |

### On concurrency

Measured against a real server: twenty chained sessions took 56 s sequentially,
12 s at concurrency 5, and 14 s at concurrency 20. It is **not** a
more-is-better dial — throughput peaks in single digits and then degrades. All
sessions still succeeded at 20; they simply took longer.

### On session lifetime

This is how a policy server expresses a periodic reauthentication timer, in
terms of RFC 2865: Session-Timeout (27) says how long, Termination-Action (29)
says what happens next.

- **Re-authenticate** is Termination-Action 1, RADIUS-Request. The exchange runs
  again and the clock resets, so it repeats.
- **Terminate** sends Accounting-Stop with Acct-Terminate-Cause 5
  (Session-Timeout) and ends the session.

A server that supplies its own Session-Timeout overrides what you set here,
which is what makes this useful for *checking* a reauthentication policy rather
than only simulating one.

---

## Generate — MAC & IP Addresses

### MAC addresses → Calling-Station-Id (31)

The endpoint's MAC, and the one value that must differ per session — it is how
the server tells your simulated endpoints apart.

**Random** generates a unique MAC per session. An **OUI prefix** such as
`00-11-22` fixes the first three octets so the endpoints appear to come from one
vendor. **From list** cycles through addresses you paste, one per line.

### IP addresses → Framed-IP-Address (8)

**Random from CIDR** picks an address per session from the range you give.
**From list** cycles through what you paste. Leave the CIDR blank to send no
address at all.

---

## Generate — TEAP Parameters

This is the part specific to TEAP. Everything above describes the request; this
describes what happens inside the tunnel.

### Identity mode

How the identities inside the tunnel are decided. Applies to certificate legs —
a password leg names itself, since there is no certificate to read from.

| Mode | Outer, in the clear | Inner, in the tunnel |
|---|---|---|
| Derived from certificate | the derived identity | the derived identity |
| Anonymous | `anonymous` | the derived identities |
| Enter manually | what you type | what you type |

**Derived** reads the identity out of the certificate: the UPN first, then the
SAN email, then the Common Name for a user; `host/` plus the SAN DNS name for a
machine. This removes the most common configuration error, an identity string
that does not match what the certificate actually contains — a mismatch a server
rejects without saying why.

**Anonymous** is what a Windows supplicant does. The outer identity is visible
on the wire before the tunnel exists, so sending `anonymous` there keeps the
real identity inside the encrypted tunnel. Note the server may still select
policy on the outer identity, so an anonymous outer can land on a different rule
than a named one.

### User leg and Machine leg

Each identity is configured independently:

- **EAP-TLS** — certificate based. Pick a certificate from the Identity
  certificates you have uploaded.
- **MS-CHAPv2** — password based. Give the user name and password; this leg
  names its own identity.
- **not used** — this identity is not attempted.

Configuring both is **EAP chaining**: two identities authenticated in one tunnel
and bound together, so the server can require that a given user is on a known
machine. Mixing them works — a machine certificate with a user password is a
real Windows configuration.

The user name for an MS-CHAPv2 leg is an input to the MS-CHAPv2 challenge hash,
so it must match what the identity store holds **exactly**. `alice` and
`alice@example.com` produce different hashes, and the wrong one comes back as
`E=691 authentication failed`, which looks identical to a wrong password.

### Trusted certificate

The chain that validates the **server's** certificate.

This is not your own issuer. Client certificates and the server's EAP
certificate frequently come from different PKIs, and uploading your own issuer
here fails validation because it does not sign the server's certificate.

Leave it unset and the server is **not verified at all**. The run still
succeeds, which is exactly why it is easy to leave unverified by accident. There
is no hostname check either way — the server is reached over RADIUS, not DNS —
so this is chain, signature and validity only.

### What certificates should be sent

| Option | Sends |
|---|---|
| Full chain | the identity certificate and every certificate stored with it |
| Full chain without root | the same, minus any self-signed certificate |
| Only identity certificate | the leaf alone |

Servers already hold their trusted roots, so sending one is redundant; some
object to it. *Only identity* works when the server already holds the
intermediates.

---

## Generate — Attributes

Additional RADIUS attributes, one `TYPE=VALUE` per line, appended to what the
panels above produce.

The type may be a number or a name: `NAS-Identifier=nas-01` and `32=nas-01` are
the same thing. Values are text, or `0x`-prefixed hex for binary, which is how
you construct a vendor-specific attribute by hand.

### Compiled RADIUS attributes

The panel beneath shows the **complete** attribute list the request will carry,
built by the same code that builds the real packet — so it cannot drift from
what is actually sent.

It flags an attribute sent more than once, which happens when a panel value and
an additional attribute collide. The server decides which wins, usually the
first, so it is worth seeing before you send rather than after.

## Value templates

Called-Station-Id and any additional attribute value may be a template, rendered
**once per session** so a value that references the endpoint varies with it
rather than freezing to whichever was generated first.

| Variable | Is |
|---|---|
| `$MAC$` | this session's Calling-Station-Id |
| `$IP$` | this session's Framed-IP-Address |
| `$SESSION$` | this session's Acct-Session-Id |
| `$INDEX$` | position within the job, from 0 |
| `$SSID$` | the configured SSID, if any |

| Function | Does |
|---|---|
| `uc(x)` / `lc(x)` | upper or lower case |
| `hex(x)` | a number as hex, otherwise the bytes as hex |
| `rand(a..b)` | a fresh random integer per session |
| `pad(x,n)` | left-pad with zeros to width n |

Calls nest, innermost first:

    uc(hex(rand(4096..65535)))/uc($MAC$)/uc(hex(rand(4096..65535)))

produces a different value per session, for example
`ED9C/00-11-22-73-76-1E/8507`. The rendered value is stored with the session, so
what was actually sent is visible afterwards.

---

## Sessions

### Columns

| Column | Meaning |
|---|---|
| Status | `accepted` = Access-Accept, `rejected` = Access-Reject, `timeout` or `error` = no usable answer arrived |
| Acct | The accounting lifecycle, independent of the authentication result: started, interim (the latest Interim-Update was accepted), stopped, expired, reauthenticated, disconnected, or a `-failed` state. Hover it for the Acct-Session-Time |
| Identity, Machine | The identities used inside the tunnel |
| MAC, IP | What this session claimed to be |
| Inner methods | Which methods actually ran, e.g. `user·EAP-TLS + machine·EAP-TLS`. Two entries means chaining happened |
| Bulk | The group it was generated in |
| Authorization | What the server granted, decoded from the Access-Accept |
| Expires | When the session lifetime fires, in UTC (hover for the date), with ↻ for re-authenticate or ■ for terminate. Every Access-Accept restarts it, taking the server's Session-Timeout and Termination-Action when it sends them |
| Duration | Wall-clock time for the authentication |

An **empty Authorization** means the server granted nothing beyond the accept.
That is worth noticing: a rule meant to push a VLAN or a dACL that shows nothing
here did not match the rule you expected.

### Actions

Actions apply either to the **rows you tick** or to **every session matching the
current filter**, chosen with the scope selector. The filter option reaches rows
on pages you never opened, which matters because the table paginates at 100.

| Action | Sends |
|---|---|
| Start | Accounting-Start (Acct-Status-Type 1) |
| Interim | Accounting Interim-Update (3) |
| Stop | Accounting-Stop (2), and stops the lifetime clock |
| Re-authenticate | Runs the whole exchange again and obtains a new Class |
| Delete | Removes the rows locally; sends nothing |

Accounting is fast and runs immediately. Re-authentication takes seconds per
session, so a filter-scoped one runs in the background with a progress bar
rather than holding the page open.

**Interim updates** can also run on a timer for every accounting-started
session. The setting survives a restart. A server that supplies
Acct-Interim-Interval (85) overrides the configured period. Counters are
synthetic — this tool generates no user traffic, so byte counts are plausible
rather than real.

Deleting a session the server still considers live leaves the server believing
it is up. Send Accounting-Stop first if that matters; the Jobs page badges how
many are in that state.

### Session detail

**TEAP exchange** lists every inner method that ran: which identity type, which
method, which identity, and whether the server accepted the Crypto-Binding that
ties it to the tunnel. Two rows bound means chaining genuinely happened, not
just that two authentications occurred.

**Authorization** decodes the Access-Accept:

| Shown | Comes from |
|---|---|
| VLAN | Tunnel-Type 13 with Tunnel-Private-Group-ID (RFC 2868), tag octet handled |
| dACL | Cisco-AVPair `CiscoSecure-Defined-ACL` |
| URL redirect | Cisco-AVPair `url-redirect` |
| Filter-Id | attribute 11 |
| Session-Timeout, Idle-Timeout, Termination-Action | 27, 28, 29 |
| Class | attribute 25 — an opaque correlator, not a grant, so listed but not highlighted |
| MS-MPPE keys | listed masked as `****`, as ISE shows them: they are the access device's encryption keys, not authorization |

Below the highlights, every attribute is listed in the layout of ISE's
authentication Result — Class, timeouts, the tunnel attributes with their tags,
each `cisco-av-pair` in full — so the two can be compared line by line.

The session's details also show the **NAS-IP-Address** it was sent with. When no
endpoint IP was set, the IP row shows that address, labelled as such.

**Exchange** is the protocol timeline. Outbound entries are green, inbound blue,
completion green and failures rust. Each step shows its clock time in your
browser's timezone, to match against the server's live log; hover it for the
offset from the start of the run.

---

## Certificates

Two jobs that are easy to confuse, usually issued by different authorities.

**Trusted** validates the server. **Identity** is what the client presents, as a
user or a machine.

| Field | Notes |
|---|---|
| Friendly name | Your label; the only thing besides type you can change later |
| Type | Trusted, Identity — User, or Identity — Machine |
| Certificate | A PEM bundle, or PKCS#12 (`.p12`/`.pfx`). Extra certificates in a bundle become the chain |
| Private key | Required for identity certificates. A key that does not match its certificate is rejected on upload |
| PKCS#12 passphrase | Only for `.p12`/`.pfx` |

Subject, issuer, serial, thumbprint and validity are read from the file on
upload, so the list can warn about a certificate that has expired or is about to
— a cause of rejections that otherwise looks like a policy problem.

**View** opens every field of every certificate in the entry, leaf first:
subject and issuer by attribute, serial, signature algorithm, public key,
validity, SHA-256 and SHA-1 fingerprints, and each extension decoded — the SAN
with its UPN, Key Usage, Extended Key Usage, CRL and AIA locations — with the
PEM to copy. Whether a private key is stored is shown; the key itself never is.

Only the name and type can be edited afterwards. Everything else comes from the
file; replacing the content means uploading again.

---

## Servers

| Field | Notes |
|---|---|
| Name | Your label |
| Address | Must be what the server sees as the source of the request |
| Auth port, Acct port | 1812 and 1813 by default |
| Shared secret | Encrypted at rest and never shown again. Blank on edit leaves the stored one alone |
| CoA enabled | Whether this server is expected to send Change-of-Authorization to udp/3799 |

A CoA request is accepted if it is signed with a shared secret belonging to one
of your servers, whatever address it arrives from — a policy server may send CoA
from a different interface than its RADIUS address names. One that is not signed
with a known secret is discarded in silence, as RFC 5176 requires.

---

## Jobs

Each run with its progress and outcome. Selecting jobs and deleting them removes
**their sessions too** — sessions belong to the job that created them.

A running job cannot be deleted; cancel it first, so its tasks are not removed
from underneath themselves.

The **live** badge counts sessions the server still considers active because
accounting was started and never stopped.
