#!/usr/bin/env python3
"""
Toy end-to-end demo of TLS 1.3 certificate inspection via MPC.

No live TLS server is needed. This script:

  1. Builds a synthetic TLS 1.3 handshake record containing a fake
     Certificate message (same helpers used in the unit tests).
  2. "Encrypts" it with AES-128 counter mode, exactly as a real TLS 1.3
     server would encrypt handshake records with AES-128-GCM.
  3. Finds which AES-GCM blocks contain the Certificate message, and which
     block holds its 4-byte handshake header (msg_type || length).
  4. Derives the AES-GCM counter blocks for the header and body blocks.
  5. Writes real MP-SPDZ input files for P0 (client) and P1 (MB).
  6. Compiles cert_inspect.mpc for the actual block count + header
     ciphertext and RUNS the real MPC protocol (semi-party.x, both
     parties, localhost).
  7. Parses the revealed keystream from the MPC's stdout, decrypts the
     certificate blocks, and confirms the recovered bytes match the
     original certificate exactly.

Three scenarios:
  1. Honest MB — everything matches, certificate is revealed and parsed.
  2. Tampered MB — the MB's body counter blocks don't match the client's
     (e.g. wrong sequence number); the MPC aborts before revealing any
     keystream.
  3. Malicious client — the client tries to relabel a non-certificate
     block (EncryptedExtensions, msg_type 0x08) as "the certificate."
     The counters legitimately match (both parties agree on the wire
     position), but the in-circuit header-type check fails, and the MPC
     refuses to reveal anything. This is the defense against a
     compromised/malicious client tricking the MB into decrypting data
     it was never meant to see (TLS 1.3 hides the outer record content
     type, so the MB cannot tell handshake vs. application-data records
     apart from ciphertext alone -- the header check is what closes
     that gap).

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


def build_synthetic_record():
    """
    Shared synthetic TLS 1.3 handshake record used by all scenarios:
    EncryptedExtensions (16 bytes, block 0) followed by a Certificate
    message starting exactly at block 1 (block-aligned, per the
    reference implementation's current limitation).
    """
    key = bytes(range(16))
    base_iv = bytes(range(12))
    seqnum = 0

    ext_body = b'\x00' * 12  # 4-byte header + 12-byte body = 16 bytes = 1 block
    ext_msg = bytes([EXT_MSG_TYPE]) + struct.pack('>I', len(ext_body))[1:] + ext_body
    assert len(ext_msg) == 16, "EncryptedExtensions must be exactly one block"

    fake_der = b'\x30\x82\x01\x00' + b'\xAB' * 60
    cert_msg = build_cert_message(fake_der)
    plaintext = ext_msg + cert_msg

    ciphertext = encrypt_record(plaintext, key, base_iv, seqnum)
    cert_block_indices = find_cert_block_indices(plaintext)
    n_total_blocks = math.ceil(len(ciphertext) / 16)
    all_ctrs = build_counter_blocks(base_iv, seqnum, n_total_blocks)

    return {
        'key': key, 'base_iv': base_iv, 'seqnum': seqnum,
        'fake_der': fake_der, 'plaintext': plaintext, 'ciphertext': ciphertext,
        'cert_block_indices': cert_block_indices, 'all_ctrs': all_ctrs,
    }


# ---------------------------------------------------------------------------
# MPC orchestration
# ---------------------------------------------------------------------------

def write_inputs(ctr_hdr: bytes, client_body_ctrs: list, mb_body_ctrs: list,
                 key: bytes):
    """
    P0 (client) file order: header counter, key, body counters.
    P1 (MB)     file order: header counter, body counters.
    Matches the read order in cert_inspect.mpc.
    """
    with open(os.path.join(PLAYER_DATA, 'Input-P0-0'), 'w') as f:
        f.write(f"{int.from_bytes(ctr_hdr, 'big')}\n")
        f.write(f"{int.from_bytes(key, 'big')}\n")
        for ctr in client_body_ctrs:
            f.write(f"{int.from_bytes(ctr, 'big')}\n")
    with open(os.path.join(PLAYER_DATA, 'Input-P1-0'), 'w') as f:
        f.write(f"{int.from_bytes(ctr_hdr, 'big')}\n")
        for ctr in mb_body_ctrs:
            f.write(f"{int.from_bytes(ctr, 'big')}\n")


def compile_and_run(n: int, ct_hdr_int: int) -> str:
    prog = f"cert_inspect-{n}-{ct_hdr_int}"
    print(f"  Compiling cert_inspect for n={n} block(s), header ciphertext bound in ...")
    subprocess.run(
        [sys.executable, "compile.py", "cert_inspect", str(n), str(ct_hdr_int)],
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
    print("SCENARIO 1: Honest MB — certificate is revealed")
    print("=" * 70)

    rec = build_synthetic_record()
    cert_block_indices = rec['cert_block_indices']
    all_ctrs = rec['all_ctrs']
    ciphertext = rec['ciphertext']
    plaintext = rec['plaintext']
    key = rec['key']

    header_idx = cert_block_indices[0]
    ctr_hdr = all_ctrs[header_idx]
    ct_hdr = ciphertext[header_idx*16:(header_idx+1)*16]
    cert_ctrs = [all_ctrs[i] for i in cert_block_indices]
    n = len(cert_ctrs)

    print(f"\nSynthetic handshake record: {len(plaintext)} bytes plaintext")
    print(f"Certificate found at AES-GCM block indices: {cert_block_indices}")
    print(f"Header block: {header_idx}  Body blocks to reveal via MPC: {n}")

    write_inputs(ctr_hdr, cert_ctrs, cert_ctrs, key)
    output = compile_and_run(n, int.from_bytes(ct_hdr, 'big'))

    if "header check failed" in output or "counter MISMATCH" in output:
        print("\n!! Unexpected rejection in honest scenario:")
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

    original = plaintext[header_idx*16 : header_idx*16 + len(recovered)]

    print(f"\nMPC verified the header is a Certificate message (0x0B) and")
    print(f"revealed {n} keystream block(s) to the MB.")
    print(f"Recovered bytes match original plaintext: {recovered == original}")

    if recovered != original:
        print("MISMATCH!")
        print("  expected:", original.hex())
        print("  got:     ", recovered.hex())
        return False

    certs = extract_cert_der_from_record(recovered)
    print(f"\nParsed {len(certs)} certificate(s) from MPC-revealed plaintext.")
    print(f"Leaf cert DER matches original: {certs and certs[0] == rec['fake_der']}")

    print("\n>>> Certificate successfully recovered via MPC without the MB ever")
    print(">>> learning the server handshake traffic key. <<<")
    return True


def scenario_tampered():
    print("\n" + "=" * 70)
    print("SCENARIO 2: Tampered MB — body counters DON'T match, MPC aborts")
    print("=" * 70)

    rec = build_synthetic_record()
    cert_block_indices = rec['cert_block_indices']
    all_ctrs = rec['all_ctrs']
    ciphertext = rec['ciphertext']
    base_iv = rec['base_iv']
    key = rec['key']

    header_idx = cert_block_indices[0]
    ctr_hdr = all_ctrs[header_idx]        # header counter: both parties agree
    ct_hdr = ciphertext[header_idx*16:(header_idx+1)*16]
    client_body_ctrs = [all_ctrs[i] for i in cert_block_indices]
    n = len(client_body_ctrs)

    # MB claims a different (bogus) record for the body -- e.g. wrong
    # sequence number, simulating an attempt to get keystream for
    # ciphertext it didn't actually observe on the wire.
    bogus_ctrs = build_counter_blocks(base_iv, rec['seqnum'] + 1, n)

    write_inputs(ctr_hdr, client_body_ctrs, bogus_ctrs, key)
    output = compile_and_run(n, int.from_bytes(ct_hdr, 'big'))

    aborted = "Aborting: counter mismatch detected" in output
    leaked = "Keystream block" in output

    print(f"\nHeader check passed (both parties agree on the header block).")
    print(f"MPC detected body counter mismatch and aborted: {aborted}")
    print(f"Any keystream leaked despite mismatch: {leaked}")

    if aborted and not leaked:
        print("\n>>> MPC correctly refused to reveal keystream for unverified")
        print(">>> ciphertext. The binding property holds. <<<")
        return True
    else:
        print("\n!! Security property violated or output unexpected:")
        print(output)
        return False


def scenario_relabeling_attack():
    print("\n" + "=" * 70)
    print("SCENARIO 3: Malicious client relabels a non-certificate block")
    print("=" * 70)

    rec = build_synthetic_record()
    all_ctrs = rec['all_ctrs']
    ciphertext = rec['ciphertext']
    key = rec['key']

    # Attacker claims block 0 (EncryptedExtensions, msg_type 0x08) is "the
    # certificate." The counters are genuine wire values -- both parties
    # correctly agree this is block 0 of the real record -- so the existing
    # counter-match check alone would NOT catch this.
    attack_idx = 0
    ctr_hdr = all_ctrs[attack_idx]
    ct_hdr = ciphertext[attack_idx*16:(attack_idx+1)*16]
    body_ctrs = [all_ctrs[attack_idx]]
    n = 1

    print(f"\nAttacker claims block {attack_idx} (actually EncryptedExtensions, "
         f"type 0x{EXT_MSG_TYPE:02x}) is the Certificate message.")
    print("Counters legitimately match on both sides (real wire position).")

    write_inputs(ctr_hdr, body_ctrs, body_ctrs, key)
    output = compile_and_run(n, int.from_bytes(ct_hdr, 'big'))

    header_rejected = "header check failed" in output
    leaked = "Keystream block" in output

    print(f"\nMPC header-type check rejected the mislabeled block: {header_rejected}")
    print(f"Any keystream leaked despite counters matching: {leaked}")

    if header_rejected and not leaked:
        print("\n>>> Even though the counters matched, the MPC's in-circuit")
        print(">>> header check caught the mislabeling and revealed nothing. <<<")
        return True
    else:
        print("\n!! Security property violated or output unexpected:")
        print(output)
        return False


if __name__ == '__main__':
    ok1 = scenario_honest()
    ok2 = scenario_tampered()
    ok3 = scenario_relabeling_attack()

    print("\n" + "=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"Scenario 1 (honest MB, cert revealed):              {'PASS' if ok1 else 'FAIL'}")
    print(f"Scenario 2 (tampered MB, MPC aborts):                {'PASS' if ok2 else 'FAIL'}")
    print(f"Scenario 3 (relabeling attack, MPC aborts):          {'PASS' if ok3 else 'FAIL'}")
    sys.exit(0 if (ok1 and ok2 and ok3) else 1)
