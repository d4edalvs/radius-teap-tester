#!/usr/bin/env bash
# Example: TEAP with EAP chaining (user + machine EAP-TLS) against a RADIUS server.
# Put the RADIUS shared secret in the environment so it stays out of shell history.
set -euo pipefail

export RSECRET="your-radius-shared-secret"

teap-tester \
  --radius-host 192.0.2.10 \
  --radius-port 1812 \
  --radius-secret-env RSECRET \
  --identity "user@lab.local" \
  --machine-identity "host/pc01.lab.local" \
  --client-cert ./certs/user.pem \
  --client-key  ./certs/user.key \
  --machine-cert ./certs/machine.pem \
  --machine-key  ./certs/machine.key \
  --ca-chain ./certs/ca-chain.pem \
  --source-ip 192.0.2.50 \
  --verbose
