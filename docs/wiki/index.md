# TEAP Tester

A TEAP (EAP type 55) client for testing RADIUS authentication, with EAP
chaining: a user EAP-TLS method and a machine EAP-TLS method inside one
TEAP tunnel, bound together by the RFC 7170 Crypto-Binding.

## Pages

- **Servers** — RADIUS servers. Shared secrets are encrypted at rest.
- **Certificates** — Trusted (CA chains validating the server) and Identity
  (user and machine client certificates).
- **Generate** — build and run sessions.
- **Sessions** — what was generated, with the full protocol timeline.
