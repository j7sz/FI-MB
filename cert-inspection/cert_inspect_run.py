"""
End-to-end orchestration for TLS 1.3 certificate inspection.

Flow:
  1. Client connects to a TLS 1.3 server (AES-128-GCM).
  2. tlslite-ng captures the server handshake traffic key, the encrypted
     handshake records, and the decrypted handshake record payloads.
  3. The client locates the Certificate message inside the decrypted records
     and identifies which AES-GCM block indices span it, plus the block
     containing its 4-byte handshake header (msg_type || length).
  4. For each block, the client computes the AES-GCM counter value (CTR_i).
  5. The client writes its MPC inputs (header counter, key, body counters)
     to Player-Data/Input-P0-0.
  6. The MB writes its MPC inputs (header counter, body counters observed
     from wire) to Player-Data/Input-P1-0.
  7. Both parties compile and run:
       compile.py cert_inspect <n> <ct_hdr>
       Scripts/semi.sh cert_inspect-<n>-<ct_hdr>
     The MPC first verifies, INSIDE the circuit, that the header decrypts
     to msg_type == 0x0B (Certificate) — without revealing the header
     plaintext — before revealing any keystream. This prevents a
     malicious/compromised client from mislabeling a non-certificate block
     (e.g. live application data) as "the certificate" to get the MB to
     decrypt it; TLS 1.3 hides the outer record content type, so the MB
     cannot otherwise tell handshake records from application data records
     apart from ciphertext alone.
  8. The MB XORs each keystream with the ciphertext block and parses the
     resulting X.509 DER certificate for crypto inventory.

Counter block derivation (TLS 1.3 + AES-128-GCM):
  record_IV = server_hs_iv XOR (b'\\x00'*4 + seqnum.to_bytes(8, 'big'))
  J_0        = record_IV + b'\\x00\\x00\\x00\\x01'
  CTR_i      = INC_32^(i+1)(J_0)   (i = 0, 1, 2, ...)
"""

import os
import sys
import math
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tls-test'))
sys.path.insert(0, os.path.dirname(__file__))

from tls_hs_extract import tls_hs_connect
from find_cert_blocks import (
    find_cert_block_indices,
    extract_cert_der_from_record,
    parse_certificate_der,
)

MP_SPDZ_DIR = os.path.join(os.path.dirname(__file__), '..', 'mp-spdz')


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def inc_32(iv: bytes) -> bytes:
    """Increment the low 32 bits of a 16-byte counter block."""
    val = int.from_bytes(iv, 'big')
    inc = ((val >> 32) << 32) ^ (((val & 0xffffffff) + 1) & 0xffffffff)
    return inc.to_bytes(16, 'big')


def build_counter_blocks(base_iv: bytes, seqnum: int, n_blocks: int) -> list:
    """
    Compute the AES-GCM counter blocks CTR_0 .. CTR_{n-1} for the TLS 1.3
    record identified by seqnum.

    base_iv  — server handshake fixedNonce (12 bytes)
    seqnum   — record sequence number under the server HS key
    n_blocks — number of AES-GCM data blocks in the record
    """
    # TLS 1.3 per-record nonce: base_iv XOR (4 zero bytes || seqnum as 8 bytes)
    seqnum_bytes = (0).to_bytes(4, 'big') + seqnum.to_bytes(8, 'big')
    record_iv = xor_bytes(base_iv + b'\x00' * 4, seqnum_bytes)  # 12 + 4 = 16 bytes

    # J_0 = record_iv (12 bytes) || 0x00000001
    J_0 = record_iv[:12] + b'\x00\x00\x00\x01'

    counters = []
    ctr = J_0
    for _ in range(n_blocks):
        ctr = inc_32(ctr)
        counters.append(ctr)
    return counters


def write_mpc_inputs(server_hs_key: bytes, server_hs_iv: bytes,
                     cert_record_idx: int, cert_block_indices: list,
                     enc_record: bytes):
    """
    Write MPC input files for cert_inspect.mpc, and return (n, ct_hdr) so
    the caller can compile the circuit with:
        compile.py cert_inspect <n> <ct_hdr>

    Client (P0) supplies (in this order): header counter, key, body counters.
    MB     (P1) supplies (in this order): header counter, body counters.

    NOTE: this reference implementation assumes the Certificate message
    header (msg_type + 3-byte length) is 16-byte-block-aligned, i.e. the
    Certificate message starts exactly on an AES-GCM block boundary. This
    holds for the synthetic records used in the demo/tests; handling an
    unaligned header (split across two blocks) is a straightforward but
    more involved extension left as future work.
    """
    n_record_blocks = math.ceil(len(enc_record) / 16)
    all_ctrs = build_counter_blocks(server_hs_iv, cert_record_idx,
                                    n_record_blocks)

    cert_ctrs = [all_ctrs[i] for i in cert_block_indices]
    n = len(cert_ctrs)

    header_block_idx = cert_block_indices[0]
    if (header_block_idx * 16) % 16 != 0:
        raise NotImplementedError(
            "Certificate header is not block-aligned; unsupported by this "
            "reference implementation.")
    ctr_hdr = all_ctrs[header_block_idx]
    ct_hdr  = enc_record[header_block_idx*16:(header_block_idx+1)*16]

    player_data = os.path.join(MP_SPDZ_DIR, 'Player-Data')

    # P0 (client): header counter, key, then body counters
    with open(os.path.join(player_data, 'Input-P0-0'), 'w') as f:
        f.write(f"{int.from_bytes(ctr_hdr, 'big')}\n")
        f.write(f"{int.from_bytes(server_hs_key, 'big')}\n")
        for ctr in cert_ctrs:
            f.write(f"{int.from_bytes(ctr, 'big')}\n")

    # P1 (MB): header counter, then body counters, derived from the
    # encrypted record it observed on the wire (simulating an honest MB).
    with open(os.path.join(player_data, 'Input-P1-0'), 'w') as f:
        f.write(f"{int.from_bytes(ctr_hdr, 'big')}\n")
        for ctr in cert_ctrs:
            f.write(f"{int.from_bytes(ctr, 'big')}\n")

    ct_hdr_int = int.from_bytes(ct_hdr, 'big')
    print(f"MPC inputs written — {n} certificate block(s).")
    print(f"Run: cd {MP_SPDZ_DIR} && "
         f"python3 compile.py cert_inspect {n} {ct_hdr_int} && "
         f"Scripts/semi.sh cert_inspect-{n}-{ct_hdr_int}")
    return cert_ctrs, n, ct_hdr_int


def mb_decrypt_cert_blocks(enc_record: bytes, keystreams: list,
                            cert_block_indices: list) -> bytes:
    """
    MB-side: XOR each cert ciphertext block with its keystream to recover
    the certificate plaintext bytes.
    """
    result = bytearray()
    for block_idx, keystream in zip(cert_block_indices, keystreams):
        ct_block = enc_record[block_idx*16 : (block_idx+1)*16]
        result.extend(xor_bytes(ct_block, keystream))
    return bytes(result)


if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '1.1.1.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 853

    print(f"Connecting to {host}:{port} ...")
    conn = tls_hs_connect(host, port)

    print(f"Handshake complete.  {len(conn.hs_decrypted_records)} encrypted HS record(s) received.")
    print(f"Server HS key: {conn.server_hs_key.hex()}")
    print(f"Server HS IV:  {conn.server_hs_iv.hex()}")

    # Locate the record containing the Certificate message
    cert_record_idx  = None
    cert_block_idxs  = None
    cert_plaintext   = None
    for rec_seq, plaintext in enumerate(conn.hs_decrypted_records):
        indices = find_cert_block_indices(plaintext)
        if indices:
            cert_record_idx  = rec_seq
            cert_block_idxs  = indices
            cert_plaintext   = plaintext
            break

    if cert_record_idx is None:
        print("ERROR: Certificate message not found in captured handshake records.")
        sys.exit(1)

    enc_record = conn.hs_encrypted_records[cert_record_idx]
    print(f"\nCertificate is in HS record #{cert_record_idx}  "
          f"({len(enc_record)} bytes encrypted)")
    print(f"AES-GCM block indices: {cert_block_idxs}")

    # Show certificate chain info (client has plaintext, so can parse directly)
    certs = extract_cert_der_from_record(cert_plaintext)
    print(f"\nCertificate chain: {len(certs)} certificate(s)")
    for i, der in enumerate(certs):
        info = parse_certificate_der(der)
        label = "Leaf" if i == 0 else f"Intermediate {i}"
        print(f"\n  [{label}]")
        for k, v in info.items():
            print(f"    {k}: {v}")

    # Write MPC inputs so both parties can run cert_inspect.mpc
    print("\n=== Writing MPC inputs ===")
    cert_ctrs, n, ct_hdr_int = write_mpc_inputs(
        conn.server_hs_key, conn.server_hs_iv,
        cert_record_idx, cert_block_idxs, enc_record,
    )
