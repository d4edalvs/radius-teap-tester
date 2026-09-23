# Certificates: which goes where

Two different jobs, and they are usually issued by different authorities.

## Trusted certificates

The CA chain that validates the **server's** EAP certificate. This is the
issuer of the RADIUS server's identity, not of your client certificates.

A common and confusing failure: your client certificates come from one PKI and
the RADIUS server's certificate from another. Uploading your own issuer as the
trusted chain will fail validation, because it does not sign the server's
certificate.

Omit the trusted certificate and the server is not verified at all. The
authentication still succeeds, which is exactly why it is easy to leave
unverified by accident.

## Identity certificates

The client certificates presented inside the tunnel.

- **User** — identifies the person. Identity is taken from the UPN, the SAN
  email, or the Common Name.
- **Machine** — identifies the device. Identity is `host/` followed by the SAN
  DNS name, which is the form ISE expects.

Both need their private key. Deriving identities from the certificate avoids
the most common configuration error: an identity string that does not match
what the certificate actually contains.

## What gets sent

- **Full chain** — the identity certificate and everything stored with it.
- **Full chain without root** — the same, minus any self-signed certificate.
  Servers already hold the root; sending it is redundant.
- **Only identity certificate** — the leaf alone. Works when the server already
  holds the intermediates.
