# What TEAP is

TEAP (Tunneled EAP) is EAP method type 55, defined in RFC 7170. It sets up a
TLS tunnel between the supplicant and the RADIUS server, then runs one or more
inner EAP methods inside it.

## Why it exists: EAP chaining

Before TEAP, authenticating both a machine and a user meant two separate,
unlinked authentications. A laptop could present a valid machine certificate
and a valid user certificate without the server ever knowing they came from the
same device. TEAP runs both inner methods in one tunnel and binds them together
cryptographically, so the server can require that a given user is on a known
machine.

## The exchange

1. Outer identity in the clear — `anonymous` if privacy is wanted.
2. Outer TLS tunnel established; the server presents its EAP certificate.
3. Server requests an Identity-Type (User or Machine).
4. Inner EAP-TLS runs for that identity.
5. Crypto-Binding TLV proves the inner method and the tunnel share endpoints.
6. Repeat 3-5 for the second identity.
7. Result TLV; the server returns Access-Accept or Access-Reject.

## Inner methods

**EAP-TLS** — certificate-based, for both the user and the machine leg. This is
what a Windows supplicant does for certificate authentication.

**MS-CHAPv2** (RFC 2759) — password-based. Configure a password for an identity
and that leg uses MS-CHAPv2 instead of EAP-TLS; the client NAKs toward whichever
method the identity is configured for. Mutual authentication is enforced: the
server's Success message carries an authenticator response derived from the
password, and a mismatch fails the exchange rather than being ignored — a server
that does not hold the password cannot pass.

The keys that bind the method to the tunnel come from the inner method itself:
the TLS exporter for EAP-TLS, and the MPPE master keys (RFC 3079) for MS-CHAPv2.

## Crypto-Binding

The step that makes chaining meaningful. After each inner method, both sides
derive a Compound MAC from the tunnel's key material and the inner method's
session key. If they match, the same two parties ran both exchanges.

This is where implementations most often fail, because the derivation is split
across RFC 7170 sections 4.2.13 and 5.3, and a wrong value produces nothing
more informative than a reject.
