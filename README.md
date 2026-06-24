# FI-MB — Privacy-Preserving TLS Inspection via MPC

FI-MB lets an enterprise middlebox (MB) inspect specific fields inside an encrypted TLS 1.3 session **without learning the session key**. The client and MB run a secure multiparty computation (MPC) protocol that reveals only the bytes needed for a declared policy — nothing else.

---

## Architecture

```
Client (P0)                         Middlebox (P1)
──────────────────                  ──────────────────
Has: TLS session key K              Has: encrypted wire traffic
     Counter blocks CTR_i                Counter blocks CTR_i
                                         (observed from wire)
          ╔══════════════════════╗
          ║   MP-SPDZ MPC        ║
          ║  1. Verify CTR match ║
          ║  2. Compute AES(K,   ║
          ║     CTR_i) in-circuit║
          ║  3. Reveal keystream ║
          ║     to MB only       ║
          ╚══════════════════════╝
                    │
                    ▼
            MB XORs keystream ⊕ ciphertext
            → reads only the approved field
```

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

## Repository Layout

```
FI-MB/
├── aes-gcm/
│   ├── implementing_aes.py     # Pure-Python AES-128/192/256
│   └── test.py                 # AES-GCM (GCTR, GHASH, GCM_AE/AD)
├── cert-inspection/
│   ├── tls_hs_extract.py       # Patched TLSConnection that captures HS state
│   ├── find_cert_blocks.py     # Locate Certificate message in decrypted record
│   ├── cert_inspect_run.py     # End-to-end orchestration script
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
4. Decrypts each record and locates the `Certificate` message
5. Prints the full certificate chain (client has the key, so it can parse directly)
6. Writes MPC input files:

| File | Written by | Contents |
|---|---|---|
| `mp-spdz/Player-Data/Input-P0-0` | Client (P0) | Counter blocks CTR_i, then key K |
| `mp-spdz/Player-Data/Input-P1-0` | MB (P1) | Counter blocks CTR_i from wire |
| `mp-spdz/Programs/Public-Input/cert_inspect` | Client (P0) | Number of cert blocks n |

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
Run: cd mp-spdz && Scripts/semi.sh cert_inspect
```

---

### Step 3 — Run the MPC protocol

Compile the program once:

```bash
cd /path/to/FI-MB/mp-spdz
./compile.py cert_inspect
```

Then both parties run their side. On a single machine (simulation):

```bash
# Terminal 1 — Client (P0)
./semi-party.x -I 0 cert_inspect

# Terminal 2 — MB (P1)
./semi-party.x -I 1 cert_inspect
```

On two separate machines, each party runs their command; MP-SPDZ handles the network connection between them.

The MPC program (`Programs/Source/cert_inspect.mpc`) does the following inside the circuit:

1. **Counter verification** — checks that P0 and P1 supplied identical CTR blocks, binding the client's key to the exact ciphertext the MB observed on the wire. If any block mismatches, the protocol aborts.
2. **Keystream computation** — computes `AES(K, CTR_i)` for each certificate block using a garbled AES circuit. K never leaves the circuit.
3. **Keystream reveal** — outputs `keystream_i` to P1 (the MB) for each block.

Sample MPC output (P1 terminal):

```
Certificate spans 79 AES-GCM block(s)
Block 0: counter verified
Block 1: counter verified
...
Counter verification result: 1
Keystream block 0: 0x3f8a...
Keystream block 1: 0xc201...
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

The MPC counter verification also prevents replay: the MB cannot substitute a different ciphertext and have the client unknowingly compute keystreams for it. The counter blocks are derived from the record's sequence number and nonce, which both parties observe and must agree on inside the circuit.

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
3. The client writes inputs; both parties run `semi-party.x`
