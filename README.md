# FI-MB — Privacy-Preserving TLS Inspection via MPC

FI-MB lets an enterprise middlebox (MB) inspect specific fields inside an encrypted TLS 1.3 session **without learning the session key**. The client and MB run a secure multiparty computation (MPC) protocol that reveals only the bytes needed for a declared policy — nothing else.

---

## Architecture

```
Client (P0)                         Middlebox (P1)
──────────────────                  ──────────────────
Has: TLS session key K              Has: encrypted wire traffic
     Header + body CTR blocks           Header + body CTR blocks
                                         (observed from wire)
          ╔══════════════════════════════╗
          ║   MP-SPDZ MPC                ║
          ║  1. Verify header CTR match  ║
          ║  2. Decrypt header IN-CIRCUIT║
          ║     and check msg_type==0x0B ║
          ║     (Certificate) -- nothing ║
          ║     about the header itself  ║
          ║     is revealed               ║
          ║  3. Verify body CTR match     ║
          ║  4. Compute AES(K, CTR_i)     ║
          ║     in-circuit for body only  ║
          ║  5. Reveal body keystream      ║
          ║     to MB only, and only if   ║
          ║     both checks passed        ║
          ╚══════════════════════════════╝
                    │
                    ▼
            MB XORs keystream ⊕ ciphertext
            → reads only the approved field
```

Step 2 exists because TLS 1.3 hides the outer record content type — every encrypted record looks like `application_data` on the wire. Without it, a malicious or compromised client could label *any* ciphertext block "the certificate" (including live application data) and the MB would decrypt it, never knowing. See [Security: Proving Revealed Blocks Are Actually the Certificate](#security-proving-revealed-blocks-are-actually-the-certificate) below.

---

## Use Cases

| Policy | Field inspected |
|---|---|
| HTTP version check | Block(s) containing `HTTP/1.1\r\n` |
| DNS filtering (DoT/DoH) | DNS request name in the payload |
| **Certificate inspection** | TLS Certificate message in server handshake |

This guide focuses on **certificate inspection** — allowing an enterprise gateway to perform crypto inventory and discovery (key algorithms, certificate chain, validity) without terminating TLS.

---

## Why Certificate Inspection?

In TLS 1.3, the server's Certificate message is **already encrypted** by the server handshake traffic key before it reaches the wire. A passive middlebox cannot read it. Full TLS termination (MITM proxy) breaks end-to-end security.

FI-MB solves this: the client (who holds the handshake key) cooperates with the MB through MPC. The MB learns only the certificate bytes — not the key — so it can verify:

- The server uses an authorized, trusted certificate
- The certificate uses approved algorithms (e.g., RSA-2048+, ECDSA P-256)
- The certificate is not expired

---

## Security: Proving Revealed Blocks Are Actually the Certificate

**The problem.** Revealing a keystream for "the certificate blocks" is only safe if those blocks really are the Certificate message. But the client is the only party who can see the plaintext, so what stops it (if malicious or compromised) from mislabeling a different block — say, live application data — as "the certificate" and getting the MB to decrypt it? Counter-block matching alone doesn't catch this: it only proves both parties agree on *which ciphertext bytes* are being discussed, not on *what those bytes mean*. And TLS 1.3 makes this worse by design — the outer record content type is hidden, so the MB cannot independently tell a handshake record from an application-data record just by looking at ciphertext.

**The defense.** `cert_inspect.mpc` decrypts the 4-byte handshake message header (`msg_type || 3-byte length`) that precedes the claimed certificate body **inside the MPC circuit**, and checks that `msg_type == 0x0B` (Certificate) before revealing anything else. Only that single verification bit comes out — never the header plaintext. If the check fails, no keystream is computed or released for the body blocks at all.

```
1. Header counter match   -- P0 and P1 must agree on which ciphertext bytes are the header
2. Header type check      -- AES(K, CTR_hdr) XOR CT_hdr, check top byte == 0x0B, in-circuit
3. Body counter match     -- as before, for the certificate body blocks
4. Keystream reveal       -- only if 1-3 all pass
```

This turns "trust the client's claim" into an MPC-enforced predicate. `cert-inspection/toy_demo.py` includes a scenario that demonstrates this directly: a simulated malicious client relabels the (genuine, correctly-countered) `EncryptedExtensions` block as "the certificate." The counters match — it's a real position on the wire — but the header-type check fails and the MPC reveals nothing.

**What this does not (yet) cover**, as layered defense-in-depth for a production deployment:
- **Session binding** — bind each MPC run to a session identifier (e.g. a hash of `ClientHello.random || ServerHello.random`) and allow only one certificate reveal per handshake, so a malicious client can't make repeated attempts against the same session hoping one slips through.
- **Post-hoc structural validation** — after a reveal, the MB should still DER-parse the recovered bytes and verify the chain builds to a trusted root; this is a useful backstop and forensic signal, but by itself does *not* prevent a leak (the bytes are already decrypted by the time this runs) — it only detects one after the fact.
- **Least privilege on the MB side** — log and rate-limit `cert_inspect` invocations per client identity, since a hardened circuit doesn't eliminate the value of limiting blast radius.

**Known limitation of the current implementation:** the header-type check assumes the Certificate message starts exactly on a 16-byte AES-GCM block boundary. Handling an unaligned header (split across two blocks) is a straightforward but more involved bit-shift extension, left as future work — see the docstring in `cert_inspect_run.py:write_mpc_inputs`.

---

## Repository Layout

```
FI-MB/
├── aes-gcm/
│   ├── implementing_aes.py     # Pure-Python AES-128/192/256
│   └── test.py                 # AES-GCM (GCTR, GHASH, GCM_AE/AD)
├── cert-inspection/
│   ├── tls_hs_extract.py       # Patched TLSConnection that captures HS state
│   ├── find_cert_blocks.py     # Locate Certificate message in decrypted record
│   ├── cert_inspect_run.py     # End-to-end orchestration script (live server)
│   ├── toy_demo.py             # Runs the real MPC protocol against synthetic data
│   └── test_cert_inspection.py # 21 offline unit tests
├── mp-spdz/
│   └── Programs/Source/
│       ├── cert_inspect.mpc    # MPC program for certificate inspection
│       ├── jason_aes.mpc       # AES-GCM IV binding (HTTP use case)
│       ├── jason_aes2.mpc
│       ├── jason_aes3.mpc
│       └── jason_aes4.mpc
├── tls-test/
│   ├── jason_tls.py            # TLS 1.3 client (AES-128-GCM)
│   └── tlslite-ng-0.8.0-alpha40/  # Patched tlslite-ng library
└── split_blocks.py             # Find HTTP version block indices
```

---

## Prerequisites

### Python dependencies

```bash
pip install ecdsa
```

The AES implementation (`aes-gcm/implementing_aes.py`) is pure Python — no C extensions needed.

### MP-SPDZ

Follow the [MP-SPDZ build instructions](https://github.com/data61/MP-SPDZ) inside `mp-spdz/`. The certificate inspection program uses the semi-honest protocol (`semi-party.x`).

The AES-128 Bristol Fashion circuit used by `cert_inspect.mpc` is not checked into this repo (it's fetched on demand, same as upstream MP-SPDZ's `make Programs/Circuits`). Fetch it once:

```bash
cd mp-spdz
git clone --depth 1 https://github.com/mkskeller/bristol-fashion Programs/Circuits
```

---

## Certificate Inspection: Step-by-Step

### Step 1 — Verify the pipeline works offline

Run the unit tests before connecting to any live server:

```bash
cd /path/to/FI-MB/cert-inspection
python test_cert_inspection.py -v
```

Expected output:

```
test_consecutive_blocks_differ ... ok
test_each_block_is_16_bytes ... ok
test_j0_derivation ... ok
...
test_decrypt_cert_blocks_recovers_plaintext ... ok
test_wrong_key_gives_garbage ... ok
----------------------------------------------------------------------
Ran 21 tests in 0.018s

OK
```

The end-to-end test (`TestEndToEndBlockDecryption`) builds a synthetic TLS handshake record, AES-GCM encrypts it, discovers the certificate blocks, derives counter blocks, decrypts only those blocks, and verifies the plaintext matches exactly.

---

### Step 1b — Toy demo with the *real* MPC protocol (no live server needed)

`test_cert_inspection.py` simulates the keystream computation directly in Python. `toy_demo.py` goes one step further: it runs the **actual MP-SPDZ MPC protocol** (`semi-party.x`, both parties, over localhost) against a synthetic certificate, so you can see the real thing work end to end.

```bash
cd /path/to/FI-MB/cert-inspection
python3 toy_demo.py
```

What it does:

1. Builds a synthetic TLS 1.3 handshake record: `EncryptedExtensions` (block 0) followed by a Certificate message starting exactly at block 1
2. AES-encrypts it exactly as a real TLS 1.3 server would (AES-128 counter mode)
3. Finds the AES-GCM block indices spanning the Certificate message, and the block containing its 4-byte handshake header
4. Derives the counter blocks and writes real MP-SPDZ input files (header counter + body counters)
5. Compiles `cert_inspect.mpc` for the actual block count and header ciphertext, and runs both MPC parties
6. Parses the revealed keystream from MPC output, decrypts the cert blocks, and confirms the recovered bytes match the original exactly
7. Runs a second scenario where the MB's body counter blocks are tampered (wrong sequence number) and confirms the MPC aborts **without leaking any keystream**
8. Runs a third scenario where a simulated malicious client relabels the (correctly-countered) `EncryptedExtensions` block as "the certificate" and confirms the in-circuit header-type check catches it — see [Security](#security-proving-revealed-blocks-are-actually-the-certificate) above

Expected output (abridged):

```
======================================================================
SCENARIO 1: Honest MB — certificate is revealed
======================================================================

Certificate found at AES-GCM block indices: [1, 2, 3, 4, 5]
Header block: 1  Body blocks to reveal via MPC: 5
  Compiling cert_inspect for n=5 block(s), header ciphertext bound in ...
  Running MPC (both parties, localhost) ...

MPC verified the header is a Certificate message (0x0B) and
revealed 5 keystream block(s) to the MB.
Recovered bytes match original plaintext: True
Parsed 1 certificate(s) from MPC-revealed plaintext.
Leaf cert DER matches original: True

======================================================================
SCENARIO 2: Tampered MB — body counters DON'T match, MPC aborts
======================================================================

Header check passed (both parties agree on the header block).
MPC detected body counter mismatch and aborted: True
Any keystream leaked despite mismatch: False

======================================================================
SCENARIO 3: Malicious client relabels a non-certificate block
======================================================================

Attacker claims block 0 (actually EncryptedExtensions, type 0x08) is the Certificate message.
Counters legitimately match on both sides (real wire position).
MPC header-type check rejected the mislabeled block: True
Any keystream leaked despite counters matching: False

======================================================================
RESULT
======================================================================
Scenario 1 (honest MB, cert revealed):              PASS
Scenario 2 (tampered MB, MPC aborts):                PASS
Scenario 3 (relabeling attack, MPC aborts):          PASS
```

This is the strongest evidence the technique works: real garbled-AES computation inside MP-SPDZ, real counter-verification logic, and proof both that a tampered MB gets nothing *and* that a malicious client can't talk its way past the header check.

> Note: `cert_inspect.mpc`'s block count `n` and header ciphertext must be known at **compile time** (MP-SPDZ's `sbits`-backed arrays can't be sized from a runtime `public_input()`, and the header ciphertext is baked in as a circuit constant since it's public wire data anyway), so `toy_demo.py` calls `compile.py cert_inspect <n> <ct_hdr>` before each MPC run. In production, the client and MB should agree on `n` and exchange the header ciphertext out of band before compiling.

---

### Step 2 — Client connects and captures handshake state

```bash
cd /path/to/FI-MB/cert-inspection
python cert_inspect_run.py <host> <port>
```

Examples:

```bash
python cert_inspect_run.py 1.1.1.1 853      # Cloudflare DNS-over-TLS
python cert_inspect_run.py google.com 443
python cert_inspect_run.py cloudflare.com 443
```

The script:
1. Connects via TLS 1.3 / AES-128-GCM
2. Captures the server handshake traffic key and IV
3. Records every encrypted handshake record (what the MB sees on the wire)
4. Decrypts each record and locates the `Certificate` message and its header block
5. Prints the full certificate chain (client has the key, so it can parse directly)
6. Writes MPC input files:

| File | Written by | Contents (in order) |
|---|---|---|
| `mp-spdz/Player-Data/Input-P0-0` | Client (P0) | Header counter, key K, body counter blocks CTR_i |
| `mp-spdz/Player-Data/Input-P1-0` | MB (P1) | Header counter, body counter blocks CTR_i from wire |

`n` (body block count) and the header ciphertext are printed as **compile-time** arguments for `compile.py` (see Step 3) rather than written to a public-input file, since `sbits` arrays and the header-check constant must be sized/bound at compile time.

Sample output:

```
Connecting to 1.1.1.1:853 ...
Handshake complete. 3 encrypted HS record(s) received.
Server HS key: a3f1...
Server HS IV:  00c2...

Certificate is in HS record #1  (1234 bytes encrypted)
AES-GCM block indices: [3, 4, 5, ..., 81]

Certificate chain: 2 certificate(s)

  [Leaf]
    subject:           CN=cloudflare-dns.com,O=Cloudflare\, Inc.,L=...
    issuer:            CN=DigiCert TLS Hybrid ECC SHA384 2020 CA1,...
    not_before:        2024-01-15T00:00:00+00:00
    not_after:         2025-01-14T23:59:59+00:00
    sig_algorithm:     1.2.840.10045.4.3.3
    pub_key_algorithm: EC (secp256r1)
    pub_key_size_bits: 256

  [Intermediate 1]
    ...

MPC inputs written — 79 certificate block(s).
Run: cd mp-spdz && python3 compile.py cert_inspect 79 <ct_hdr_int> && Scripts/semi.sh cert_inspect-79-<ct_hdr_int>
```

---

### Step 3 — Run the MPC protocol

Compile the program with the actual body block count `n` and header ciphertext `ct_hdr` (both printed by `cert_inspect_run.py` in Step 2 — both parties must use the same values, since the header ciphertext is public wire data and `n` is agreed out of band):

```bash
cd /path/to/FI-MB/mp-spdz
python3 compile.py cert_inspect <n> <ct_hdr>
```

Then both parties run their side against the resulting `cert_inspect-<n>-<ct_hdr>` program. On a single machine (simulation):

```bash
# Terminal 1 — Client (P0)
./semi-party.x -I 0 cert_inspect-<n>-<ct_hdr>

# Terminal 2 — MB (P1)
./semi-party.x -I 1 cert_inspect-<n>-<ct_hdr>
```

Or use the convenience script that launches both parties locally:

```bash
Scripts/semi.sh cert_inspect-<n>-<ct_hdr>
```

On two separate machines, each party runs their own command; MP-SPDZ handles the network connection between them.

The MPC program (`Programs/Source/cert_inspect.mpc`) does the following inside the circuit:

1. **Header counter verification** — checks P0 and P1 agree on which ciphertext block is the handshake header. Mismatch aborts immediately.
2. **Header type check** — decrypts the header in-circuit and checks `msg_type == 0x0B` (Certificate) without revealing anything else about it. Failure aborts — this is what stops a malicious client from relabeling a non-certificate block (see [Security](#security-proving-revealed-blocks-are-actually-the-certificate)).
3. **Body counter verification** — checks that P0 and P1 supplied identical CTR blocks for the certificate body, binding the client's key to the exact ciphertext the MB observed on the wire. Mismatch aborts.
4. **Keystream computation** — computes `AES(K, CTR_i)` for each certificate body block using a garbled AES circuit. K never leaves the circuit.
5. **Keystream reveal** — outputs `keystream_i` to P1 (the MB) for each body block, only if steps 1-3 all passed.

Sample MPC output (P1 terminal):

```
Certificate claimed to span 79 AES-GCM block(s)
Header verified: handshake message type is Certificate (0x0B)
Block 0: counter verified
Block 1: counter verified
...
Counter verification result: 1
Keystream block 0: 84237...
Keystream block 1: 15602...
...
```

---

### Step 4 — MB decrypts and inspects the certificate

The MB XORs each received keystream block with the corresponding ciphertext block it captured from the wire:

```python
from cert_inspect_run import mb_decrypt_cert_blocks
from find_cert_blocks import extract_cert_der_from_record, parse_certificate_der

# keystreams: list of 16-byte blocks received from MPC output
# enc_record: the encrypted record the MB captured from wire
# cert_block_indices: which block indices cover the Certificate message

cert_plaintext = mb_decrypt_cert_blocks(enc_record, keystreams, cert_block_indices)
certs = extract_cert_der_from_record(cert_plaintext)

for i, der in enumerate(certs):
    info = parse_certificate_der(der)
    label = "Leaf" if i == 0 else f"Intermediate {i}"
    print(f"[{label}] {info['subject']}")
    print(f"  Algorithm: {info['pub_key_algorithm']} {info['pub_key_size_bits']} bits")
    print(f"  Valid until: {info['not_after']}")
```

---

## Privacy Guarantees

| MB learns | MB does NOT learn |
|---|---|
| Certificate chain (leaf + intermediates) | Session key K |
| Subject, issuer, key algorithm, key size | Any application data |
| Certificate validity dates | Content outside the cert blocks |
| Whether the cert passes crypto policy | Client's private key |
| — | Anything, if the client mislabels a non-certificate block (blocked by the header-type check) |

The MPC counter verification prevents replay: the MB cannot substitute a different ciphertext and have the client unknowingly compute keystreams for it. The counter blocks are derived from the record's sequence number and nonce, which both parties observe and must agree on inside the circuit. The header-type check (see [Security](#security-proving-revealed-blocks-are-actually-the-certificate)) prevents a stronger attack the counter check alone doesn't catch: a malicious client correctly pointing at real wire bytes, but *lying about what those bytes are*.

---

## AES-GCM Counter Block Derivation

For reference, the counter blocks fed into the MPC are derived as follows:

```
record_nonce (12 B) = server_hs_iv  XOR  (0x00000000 || seqnum as 8 bytes)
J_0          (16 B) = record_nonce  ||   0x00000001
CTR_i        (16 B) = INC_32^(i+1)(J_0)     i = 0, 1, 2, ...

keystream_i         = AES(K, CTR_i)
plaintext_block_i   = ciphertext_block_i  XOR  keystream_i
```

`INC_32` increments only the low 32 bits of a 128-bit counter block, matching the GCM specification (NIST SP 800-38D).

---

## Running Other Inspection Policies

### HTTP version check

```bash
cd /path/to/FI-MB
python split_blocks.py
```

Finds the 16-byte AES-GCM block(s) containing `HTTP/1.1\r\n` for use with `jason_aes.mpc`.

### Extending to new policies

1. Write a block-finder in Python (see `split_blocks.py` or `find_cert_blocks.py` as templates)
2. Write an MPC program in `mp-spdz/Programs/Source/` that takes the relevant counter blocks, verifies them, and reveals the keystream for only those blocks
3. **If the target field's identity can't be inferred from ciphertext alone** (as with TLS 1.3's hidden content types), add an in-circuit structural check — decrypt a small preceding marker under MPC and assert its value — before revealing anything, following the pattern in `cert_inspect.mpc`. Skipping this step means trusting the client's unverified claim about what the revealed bytes are.
4. The client writes inputs; both parties run `semi-party.x`
