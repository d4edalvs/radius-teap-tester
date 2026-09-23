# Common failures

Symptoms, and what actually causes them. Most of these were hit for real while
building this tool.

---

## Nothing comes back at all

The run times out and the server logs show nothing, because the request was
discarded before policy ran. Three usual causes:

**The shared secret is wrong.** A mismatched secret fails the
Message-Authenticator check and the server drops the request in silence. This is
indistinguishable from an unreachable host, so suspect it whenever a previously
working server starts timing out.

**The source address is not a configured device.** A server matches its device
definition on the address the request claims. If there is no definition for it,
the packet goes no further. Set Source IP to an address the server knows — it
does not have to be an address on your machine.

**Nothing is listening.** Check the port. Authentication is 1812, accounting is
1813, and they are configured separately.

---

## cannot send from *x.x.x.x*: no such address on this machine

You have put an address in the **bind** setting rather than the advertised one.

These are different things. The advertised NAS-IP-Address is what the request
*claims* to come from and can be anything. The bind address decides which local
interface the packet leaves by, so it must genuinely exist here. You almost
never need to set it — leave it empty.

---

## certificate verify failed

The trusted certificate does not sign the server's EAP certificate.

Check which authority issued the **server's** certificate, not your client's.
They are frequently different PKIs, and using your own issuer here is the most
common mistake. Look at the server's certificate directly if you are unsure.

If you do not want verification at all, leave the trusted certificate unset —
but note the run then succeeds without verifying anything, which is easy to do
by accident and hard to notice.

---

## E=691 authentication failed

MS-CHAPv2 rejected the credential. Two causes look identical:

**The password is wrong.**

**The user name does not match the identity store exactly.** The user name is an
input to the MS-CHAPv2 challenge hash, so `alice` and `alice@example.com`
produce different hashes and the server cannot match either. If the password is
definitely right, try the bare name.

---

## Authentication succeeds but the wrong policy applies

The request matched a more general rule than intended. The attributes that
usually drive rule selection:

- **NAS-Port-Type** — 15 wired, 19 wireless. A wired/wireless split keys off
  exactly this.
- **Called-Station-Id** — the access device, and the SSID after the colon for
  wireless.
- **Calling-Station-Id** — the endpoint MAC.
- **NAS-Identifier**, **NAS-IP-Address** — device lookup.
- **The outer identity** — a server may select policy on what it sees before the
  tunnel, so `anonymous` can land somewhere different from a named identity.

Use the compiled attribute panel on the Generate page to see exactly what will
be sent, including any attribute sent twice.

---

## Accepted, but the Authorization column is empty

The server granted nothing beyond the accept — no VLAN, no dACL, no timeouts.

If a rule was meant to push something, it did not match. This is the most useful
diagnostic the tool offers: it distinguishes "authentication worked" from "the
policy you expected ran".

---

## A single identity is rejected while chaining succeeds

The server's policy requires both identities. When asked for an identity type it
has no credential for, this client answers with a type it does have, and the
server then chooses: authenticate that one instead, ask for something else, or
apply its policy and reject.

So a single-identity failure is usually the server requiring chaining rather
than a limitation here. In a policy server that is an authorization rule
conditioned on the chaining result; relax it to allow user-only or machine-only.

---

## Machine authentication fails against Active Directory

If the machine leg uses a password and the directory rejects it, check that the
machine leg has its **own** credential. Legs never share: a machine leg with no
password of its own offers none, rather than reusing the user's.

---

## Rejected despite a valid certificate

- **Expired, or not yet valid.** The Certificates page flags both; check the
  expiry column.
- **The identity does not match the certificate.** Deriving the identity from
  the certificate removes this class of error entirely.
- **The server does not trust the issuer** of the client certificate. That is a
  separate trust store from the one validating the server.
- **The wrong chain was sent.** Try *full chain without root*: some servers
  object to being sent a root they already hold.

---

## Accounting records are ignored

**Class must be echoed back exactly** as the server sent it in the Access-Accept.
Without it the records arrive but correlate with nothing. This tool stores Class
per session and sends it automatically.

After a re-authentication the server issues a **new** Class and retires the old
one, so accounting must use the new value. Sessions are updated in place for
exactly this reason.

---

## A CoA request produces no reply

The listener answers only a request signed with a shared secret belonging to one
of your configured servers. One that is not is discarded in silence, because
there is no secret to authenticate it with and none to sign a reply with —
RFC 5176 requires exactly that.

The address it arrives from does not need to match a server definition; the
secret is what identifies the sender. If nothing answers, the secret is wrong,
or udp/3799 is not reachable — in a container it must be published, and it
cannot be bound to localhost.
