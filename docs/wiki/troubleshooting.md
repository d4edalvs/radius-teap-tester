# Common failures

## Nothing comes back at all

The server is discarding the packet before it reaches policy. Usually:

- The shared secret is wrong. A mismatched secret fails the
  Message-Authenticator check and the server drops the request silently.
- The source address is not configured as a network device on the server.
  Check that the Source IP matches a device definition.

## certificate verify failed

The trusted certificate does not sign the server's EAP certificate. Confirm
which authority issued the **server's** certificate, not your client's.

## Authentication succeeds but policy does not match

The request is being accepted by a more general rule than intended. The
attributes that usually drive policy selection:

- **NAS-Port-Type** — 15 wired, 19 wireless. A wired/wireless policy split
  keys off this.
- **Called-Station-Id** — the access device, and the SSID for wireless.
- **Calling-Station-Id** — the endpoint MAC.
- **NAS-Identifier**, **NAS-IP-Address** — device lookup.

## Rejected despite a valid certificate

- Expired or not-yet-valid certificate. The Certificates page flags both.
- The identity does not match the certificate. Deriving it from the
  certificate removes this class of error.
- The server does not trust the issuer of the client certificate.

## Accounting records are ignored

Class must be echoed back exactly as the server sent it in the Access-Accept.
Without it, records arrive but correlate with nothing.
