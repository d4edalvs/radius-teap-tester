# teap tester

A TEAP client for testing RADIUS authentication. TEAP is EAP method type 55,
defined in RFC 7170: it builds a TLS tunnel to the RADIUS server, then runs one
or two inner EAP methods inside it.

Running two — a machine identity and a user identity, bound together
cryptographically — is **EAP chaining**, and it is the thing this tool exists
for. A generic RADIUS tester can tell you an authentication was accepted. This
one can tell you which identities authenticated, by which method, whether the
server accepted the binding between them, and what authorization came back.

## Where to start

1. **[Servers](/servers)** — add your RADIUS server and its shared secret.
2. **[Certificates](/certificates)** — upload the chain that validates the
   *server's* certificate under Trusted, and your client certificates under
   Identity. These are usually different PKIs; see
   [certificates](?page_name=certificates) for why that trips people up.
3. **[Generate](/generate)** — pick the server, choose an inner method for each
   leg, and run a single session before running hundreds.
4. **[Sessions](/sessions)** — read what happened: the exchange timeline, which
   inner methods ran, and what the server granted.

## Reading

| Page | |
|---|---|
| [What TEAP is](?page_name=teap) | The protocol, why chaining exists, and what the Crypto-Binding does |
| [Certificates](?page_name=certificates) | Which certificate goes where, and what gets sent |
| [Field reference](?page_name=fields) | Every control, what it becomes on the wire, and what breaks |
| [Common failures](?page_name=troubleshooting) | Symptoms and their usual causes |

## What it does not do

- **Inner methods** are EAP-TLS and MS-CHAPv2. No MAB, no PAP — those are not
  TEAP.
- **TLS 1.2 only**, which is what RFC 7170 specifies. TEAP over TLS 1.3 is a
  separate, later specification.
- **Accounting counters are synthetic.** No user traffic is generated, so byte
  counts are plausible rather than real.
- **There is no authentication on this interface.** It holds private keys and
  RADIUS shared secrets, so keep it on localhost.
