"""
End-to-end orchestration for TLS 1.3 certificate inspection.

Flow:
  1. Client connects to a TLS 1.3 server (AES-128-GCM).
  2. tlslite-ng captures the server handshake traffic key, the encrypted
     handshake records, and the decrypted handshake record payloads.
  3. The client locates the Certificate message inside the decrypted records
     and identifies which AES-GCM block indices span it.
  4. For each certificate block, the client computes the AES-GCM counter
     value (CTR_i) that was used to generate its keystream.
  5. The client writes its MPC inputs (counter blocks + server HS key) to
     Player-Data/Input-P0-0 and the block count to Programs/Public-Input/cert_inspect.
  6. The MB writes its MPC inputs (counter blocks from wire) to
     Player-Data/Input-P1-0.
  7. Both parties run:  Scripts/semi.sh cert_inspect
     The MPC reveals the AES keystream for each cert block to the MB.
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
    Write MPC input files and public input for cert_inspect.mpc.

    Client (P0) supplies: counter blocks CTR_i (then key K last).
    MB     (P1) supplies: the same counter blocks observed from wire.
    Public:    n (number of cert blocks).
    """
    n_record_blocks = math.ceil(len(enc_record) / 16)
    # Offset from start of record to the cert-specific blocks
    all_ctrs = build_counter_blocks(server_hs_iv, cert_record_idx,
                                    n_record_blocks)

    cert_ctrs = [all_ctrs[i] for i in cert_block_indices]
    n = len(cert_ctrs)

    player_data = os.path.join(MP_SPDZ_DIR, 'Player-Data')
    pub_input   = os.path.join(MP_SPDZ_DIR, 'Programs', 'Public-Input', 'cert_inspect')

    # Public input: number of cert blocks
    with open(pub_input, 'w') as f:
        f.write(f"{n}\n")

    # P0 (client): counter blocks as big integers, then key
    with open(os.path.join(player_data, 'Input-P0-0'), 'w') as f:
        for ctr in cert_ctrs:
            f.write(f"{int.from_bytes(ctr, 'big')}\n")
        f.write(f"{int.from_bytes(server_hs_key, 'big')}\n")

    # P1 (MB): counter blocks derived from the encrypted record it observed
    # In practice the MB computes these from the wire-observed record IV + seqnum.
    # Here we write the same values (simulating an honest MB).
    with open(os.path.join(player_data, 'Input-P1-0'), 'w') as f:
        for ctr in cert_ctrs:
            f.write(f"{int.from_bytes(ctr, 'big')}\n")

    print(f"MPC inputs written — {n} certificate block(s).")
    print(f"Run: cd {MP_SPDZ_DIR} && Scripts/semi.sh cert_inspect")
    return cert_ctrs


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
    cert_ctrs = write_mpc_inputs(
        conn.server_hs_key, conn.server_hs_iv,
        cert_record_idx, cert_block_idxs, enc_record,
    )
