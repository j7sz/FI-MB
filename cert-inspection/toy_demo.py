#!/usr/bin/env python3
"""
Toy end-to-end demo of TLS 1.3 certificate inspection via MPC.

No live TLS server is needed. This script:

  1. Builds a synthetic TLS 1.3 handshake record containing a fake
     Certificate message (same helpers used in the unit tests).
  2. "Encrypts" it with AES-128 counter mode, exactly as a real TLS 1.3
     server would encrypt handshake records with AES-128-GCM.
  3. Finds which AES-GCM blocks contain the Certificate message.
  4. Derives the AES-GCM counter blocks for those cert blocks.
  5. Writes real MP-SPDZ input files for P0 (client) and P1 (MB).
  6. Compiles cert_inspect.mpc for the actual block count and RUNS the
     real MPC protocol (semi-party.x, both parties, localhost).
  7. Parses the revealed keystream from the MPC's stdout, decrypts the
     certificate blocks, and confirms the recovered bytes match the
     original certificate exactly.
  8. Runs a second "tampered" scenario where the MB's observed counter
     blocks don't match the client's, and shows the MPC aborting instead
     of leaking any keystream.

Run:
    cd cert-inspection
    python3 toy_demo.py
"""

import math
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tls-test', 'tlslite-ng-0.8.0-alpha40'))
sys.path.insert(0, HERE)

from find_cert_blocks import (
    find_cert_block_indices,
    extract_cert_der_from_record,
    CERT_MSG_TYPE,
)
from cert_inspect_run import xor_bytes, build_counter_blocks

MP_SPDZ_DIR = os.path.join(HERE, '..', 'mp-spdz')
PLAYER_DATA = os.path.join(MP_SPDZ_DIR, 'Player-Data')

_AES_PATH = os.path.join(HERE, '..', 'aes-gcm')
sys.path.insert(0, _AES_PATH)
from implementing_aes import aes_encryption as _raw_aes


def aes128_encrypt(key: bytes, block: bytes) -> bytes:
    return bytes(_raw_aes(bytearray(block), bytearray(key)))


# ---------------------------------------------------------------------------
# Synthetic handshake record (same shape as test_cert_inspection.py)
# ---------------------------------------------------------------------------

EXT_MSG_TYPE = 0x08


def build_cert_message(cert_der: bytes) -> bytes:
    entry = struct.pack('>I', len(cert_der))[1:] + cert_der + b'\x00\x00'
    cert_list = struct.pack('>I', len(entry))[1:] + entry
    body = b'\x00' + cert_list
    header = bytes([CERT_MSG_TYPE]) + struct.pack('>I', len(body))[1:]
    return header + body


def encrypt_record(plaintext: bytes, key: bytes, base_iv: bytes, seqnum: int) -> bytes:
    n = math.ceil(len(plaintext) / 16)
    ctrs = build_counter_blocks(base_iv, seqnum, n)
    keystream = [aes128_encrypt(key, ctr) for ctr in ctrs]
    out = bytearray()
    for i in range(n):
        pt = plaintext[i*16:(i+1)*16]
        out.extend(xor_bytes(pt, keystream[i][:len(pt)]))
    return bytes(out)


# ---------------------------------------------------------------------------
# MPC orchestration
# ---------------------------------------------------------------------------

def write_inputs(client_ctrs, mb_ctrs, key: bytes):
    with open(os.path.join(PLAYER_DATA, 'Input-P0-0'), 'w') as f:
        for ctr in client_ctrs:
            f.write(f"{int.from_bytes(ctr, 'big')}\n")
        f.write(f"{int.from_bytes(key, 'big')}\n")
    with open(os.path.join(PLAYER_DATA, 'Input-P1-0'), 'w') as f:
        for ctr in mb_ctrs:
            f.write(f"{int.from_bytes(ctr, 'big')}\n")


def compile_and_run(n: int) -> str:
    prog = f"cert_inspect-{n}"
    print(f"  Compiling cert_inspect for n={n} blocks ...")
    subprocess.run(
        [sys.executable, "compile.py", "cert_inspect", str(n)],
        cwd=MP_SPDZ_DIR, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(f"  Running MPC (both parties, localhost) ...")
    result = subprocess.run(
        ["Scripts/semi.sh", prog],
        cwd=MP_SPDZ_DIR, check=False,
        capture_output=True, text=True,
    )
    return result.stdout + result.stderr


def parse_keystreams(mpc_output: str, n: int) -> list:
    keystreams = [None] * n
    for line in mpc_output.splitlines():
        if line.startswith("Keystream block"):
            parts = line.split(":")
            idx = int(parts[0].split()[-1])
            value = int(parts[1].strip())
            if value < 0:
                value += 1 << 128  # sbits reveal prints two's-complement signed
            keystreams[idx] = value.to_bytes(16, 'big')
    return keystreams


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------

def scenario_honest():
    print("=" * 70)
    print("SCENARIO 1: Honest MB — counters match, certificate is revealed")
    print("=" * 70)

    key = bytes(range(16))
    base_iv = bytes(range(12))
    seqnum = 0
    fake_der = b'\x30\x82\x01\x00' + b'\xAB' * 60  # small fake DER, ~64 bytes

    ext_body = b'\x00\x00' * 5  # pad EncryptedExtensions to move cert off offset 0
    ext_msg = bytes([EXT_MSG_TYPE]) + struct.pack('>I', len(ext_body))[1:] + ext_body
    cert_msg = build_cert_message(fake_der)
    plaintext = ext_msg + cert_msg

    ciphertext = encrypt_record(plaintext, key, base_iv, seqnum)
    cert_block_indices = find_cert_block_indices(plaintext)
    n_total_blocks = math.ceil(len(ciphertext) / 16)
    all_ctrs = build_counter_blocks(base_iv, seqnum, n_total_blocks)
    cert_ctrs = [all_ctrs[i] for i in cert_block_indices]
    n = len(cert_ctrs)

    print(f"\nSynthetic handshake record: {len(plaintext)} bytes plaintext")
    print(f"Certificate found at AES-GCM block indices: {cert_block_indices}")
    print(f"Number of blocks to reveal via MPC: {n}")

    # Client and MB agree (honest case)
    write_inputs(client_ctrs=cert_ctrs, mb_ctrs=cert_ctrs, key=key)
    output = compile_and_run(n)

    if "counter MISMATCH" in output:
        print("\n!! Unexpected mismatch in honest scenario:")
        print(output)
        return False

    keystreams = parse_keystreams(output, n)
    if any(k is None for k in keystreams):
        print("\n!! Failed to parse keystream from MPC output:")
        print(output)
        return False

    recovered = bytearray()
    for idx, ks in zip(cert_block_indices, keystreams):
        ct_block = ciphertext[idx*16:(idx+1)*16]
        recovered.extend(xor_bytes(ct_block, ks))
    recovered = bytes(recovered)

    original = plaintext[cert_block_indices[0]*16 : cert_block_indices[0]*16 + len(recovered)]

    print(f"\nMPC revealed {n} keystream block(s) to the MB.")
    print(f"MB decrypted {len(recovered)} bytes.")
    print(f"Recovered bytes match original plaintext: {recovered == original}")

    if recovered != original:
        print("MISMATCH!")
        print("  expected:", original.hex())
        print("  got:     ", recovered.hex())
        return False

    # Parse the certificate out of the recovered bytes (real end-user payoff)
    full_recovered_plaintext = plaintext[:cert_block_indices[0]*16] + recovered
    certs = extract_cert_der_from_record(full_recovered_plaintext)
    print(f"\nParsed {len(certs)} certificate(s) from MPC-revealed plaintext.")
    print(f"Leaf cert DER matches original: {certs and certs[0] == fake_der}")

    print("\n>>> Certificate successfully recovered via MPC without the MB ever")
    print(">>> learning the server handshake traffic key. <<<")
    return True


def scenario_tampered():
    print("\n" + "=" * 70)
    print("SCENARIO 2: Tampered MB — counters DON'T match, MPC aborts")
    print("=" * 70)

    key = bytes(range(16))
    base_iv = bytes(range(12))
    seqnum = 0
    n = 3

    client_ctrs = build_counter_blocks(base_iv, seqnum, n)
    # MB claims a different (bogus) record -- e.g. wrong sequence number,
    # simulating an attempt to get keystream for ciphertext it didn't
    # actually observe on the wire.
    mb_ctrs = build_counter_blocks(base_iv, seqnum + 1, n)

    write_inputs(client_ctrs=client_ctrs, mb_ctrs=mb_ctrs, key=key)
    output = compile_and_run(n)

    aborted = "Aborting: counter mismatch detected" in output
    leaked = "Keystream block" in output

    print(f"\nMPC detected counter mismatch and aborted: {aborted}")
    print(f"Any keystream leaked despite mismatch: {leaked}")

    if aborted and not leaked:
        print("\n>>> MPC correctly refused to reveal keystream for unverified")
        print(">>> ciphertext. The binding property holds. <<<")
        return True
    else:
        print("\n!! Security property violated or output unexpected:")
        print(output)
        return False


if __name__ == '__main__':
    ok1 = scenario_honest()
    ok2 = scenario_tampered()

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"Scenario 1 (honest MB, cert revealed):      {'PASS' if ok1 else 'FAIL'}")
    print(f"Scenario 2 (tampered MB, MPC aborts):        {'PASS' if ok2 else 'FAIL'}")
    sys.exit(0 if (ok1 and ok2) else 1)
