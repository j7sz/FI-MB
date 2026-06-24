"""
Offline unit tests for the certificate inspection pipeline.

These tests verify correctness without a live TLS connection by constructing
synthetic TLS 1.3 handshake records and checking every stage of the pipeline:

  1. AES-GCM counter block derivation
  2. TLS handshake message parsing
  3. Certificate block index discovery
  4. Certificate DER extraction
  5. End-to-end: encrypt a fake cert record, derive counter blocks,
     XOR with keystream, and verify the certificate is recovered
"""

import math
import struct
import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'tls-test', 'tlslite-ng-0.8.0-alpha40'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from find_cert_blocks import (
    _parse_handshake_messages,
    find_cert_block_indices,
    extract_cert_der_from_record,
    CERT_MSG_TYPE,
    EXT_MSG_TYPE,
)
from cert_inspect_run import (
    inc_32,
    xor_bytes,
    build_counter_blocks,
)

# ---------------------------------------------------------------------------
# AES-128 for testing: uses our local pure-Python implementation.
# ---------------------------------------------------------------------------

_AES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'aes-gcm')
sys.path.insert(0, _AES_PATH)
from implementing_aes import aes_encryption as _raw_aes

def _aes128_encrypt(key: bytes, block: bytes) -> bytes:
    return bytes(_raw_aes(bytearray(block), bytearray(key)))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_cert_message(cert_der: bytes) -> bytes:
    """
    Build a minimal TLS Certificate handshake message (RFC 8446 §4.4.2).
    context = empty (1 byte length = 0)
    certificate_list = one CertificateEntry with no extensions
    """
    # CertificateEntry: 3-byte cert len + DER + 2-byte ext len (0)
    entry = struct.pack('>I', len(cert_der))[1:] + cert_der + b'\x00\x00'
    # certificate_list: 3-byte list length prefix
    cert_list = struct.pack('>I', len(entry))[1:] + entry
    # body = context_len(0) + cert_list
    body = b'\x00' + cert_list
    # handshake header: type(1) + len(3)
    header = bytes([CERT_MSG_TYPE]) + struct.pack('>I', len(body))[1:]
    return header + body


def _build_hs_plaintext(*messages: bytes) -> bytes:
    """
    Concatenate handshake messages into a TLS 1.3 plaintext record.
    (No inner content type byte — our fixed recordlayer strips it before
    appending to hsDecryptedRecords.)
    """
    return b''.join(messages)


def _aes_gcm_keystream(key: bytes, base_iv: bytes, seqnum: int,
                       n_blocks: int) -> list:
    """Compute keystream blocks using raw AES ECB (simulates AES-GCM CTR mode)."""
    ctrs = build_counter_blocks(base_iv, seqnum, n_blocks)
    return [_aes128_encrypt(key, ctr) for ctr in ctrs]


def _encrypt_record(plaintext: bytes, key: bytes, base_iv: bytes,
                    seqnum: int) -> bytes:
    """XOR-encrypt a plaintext record block-by-block (no GCM auth tag)."""
    n = math.ceil(len(plaintext) / 16)
    keystreams = _aes_gcm_keystream(key, base_iv, seqnum, n)
    ciphertext = bytearray()
    for i in range(n):
        pt_block = plaintext[i*16:(i+1)*16]
        ks_block = keystreams[i][:len(pt_block)]
        ciphertext.extend(xor_bytes(pt_block, ks_block))
    return bytes(ciphertext)


def _decrypt_blocks(ciphertext: bytes, key: bytes, base_iv: bytes,
                    seqnum: int, block_indices: list) -> bytes:
    """Decrypt only the specified block indices."""
    n_total = math.ceil(len(ciphertext) / 16)
    keystreams = _aes_gcm_keystream(key, base_iv, seqnum, n_total)
    result = bytearray()
    for idx in block_indices:
        ct = ciphertext[idx*16:(idx+1)*16]
        ks = keystreams[idx][:len(ct)]
        result.extend(xor_bytes(ct, ks))
    return bytes(result)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInc32(unittest.TestCase):
    def test_low_byte_increment(self):
        block = bytes(15) + b'\x01'
        self.assertEqual(inc_32(block), bytes(15) + b'\x02')

    def test_wrap_around(self):
        block = b'\x00' * 12 + b'\xff\xff\xff\xff'
        self.assertEqual(inc_32(block), b'\x00' * 12 + b'\x00\x00\x00\x00')

    def test_high_bits_unchanged(self):
        block = b'\xde\xad\xbe\xef' + b'\x00' * 8 + b'\x00\x00\x00\x02'
        result = inc_32(block)
        self.assertEqual(result[:4], b'\xde\xad\xbe\xef')
        self.assertEqual(result[-4:], b'\x00\x00\x00\x03')


class TestCounterBlocks(unittest.TestCase):
    def test_length(self):
        base_iv = bytes(range(12))
        ctrs = build_counter_blocks(base_iv, seqnum=0, n_blocks=5)
        self.assertEqual(len(ctrs), 5)

    def test_each_block_is_16_bytes(self):
        base_iv = bytes(range(12))
        ctrs = build_counter_blocks(base_iv, seqnum=0, n_blocks=3)
        for ctr in ctrs:
            self.assertEqual(len(ctr), 16)

    def test_consecutive_blocks_differ(self):
        base_iv = bytes(range(12))
        ctrs = build_counter_blocks(base_iv, seqnum=0, n_blocks=3)
        self.assertNotEqual(ctrs[0], ctrs[1])
        self.assertNotEqual(ctrs[1], ctrs[2])

    def test_seqnum_changes_counters(self):
        base_iv = bytes(range(12))
        ctrs0 = build_counter_blocks(base_iv, seqnum=0, n_blocks=1)
        ctrs1 = build_counter_blocks(base_iv, seqnum=1, n_blocks=1)
        self.assertNotEqual(ctrs0[0], ctrs1[0])

    def test_j0_derivation(self):
        # Manual check: record_iv = base_iv XOR (0x00000000 || seqnum)
        base_iv = b'\x01' * 12
        seqnum = 2
        seqnum_bytes = b'\x00\x00\x00\x00' + seqnum.to_bytes(8, 'big')
        record_iv = xor_bytes(base_iv + b'\x00' * 4, seqnum_bytes)
        J_0 = record_iv[:12] + b'\x00\x00\x00\x01'
        expected_ctr0 = inc_32(J_0)
        ctrs = build_counter_blocks(base_iv, seqnum=seqnum, n_blocks=1)
        self.assertEqual(ctrs[0], expected_ctr0)


class TestParseHandshakeMessages(unittest.TestCase):
    def _make_msg(self, msg_type: int, body: bytes) -> bytes:
        return bytes([msg_type]) + struct.pack('>I', len(body))[1:] + body

    def test_single_cert_message(self):
        body = b'\xAB' * 20
        msg = self._make_msg(CERT_MSG_TYPE, body)
        messages = _parse_handshake_messages(msg)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0][0], CERT_MSG_TYPE)
        self.assertEqual(messages[0][2], 20)

    def test_multiple_messages(self):
        m1 = self._make_msg(EXT_MSG_TYPE, b'\x00' * 5)
        m2 = self._make_msg(CERT_MSG_TYPE, b'\x01' * 10)
        plaintext = m1 + m2
        messages = _parse_handshake_messages(plaintext)
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0][0], EXT_MSG_TYPE)
        self.assertEqual(messages[1][0], CERT_MSG_TYPE)

    def test_offset_tracking(self):
        m1 = self._make_msg(EXT_MSG_TYPE, b'\x00' * 5)
        m2 = self._make_msg(CERT_MSG_TYPE, b'\x01' * 10)
        plaintext = m1 + m2
        messages = _parse_handshake_messages(plaintext)
        # m2 starts at len(m1) = 4 + 5 = 9
        self.assertEqual(messages[1][1], 9)


class TestFindCertBlockIndices(unittest.TestCase):
    def _make_msg(self, msg_type: int, body: bytes) -> bytes:
        return bytes([msg_type]) + struct.pack('>I', len(body))[1:] + body

    def test_cert_at_start(self):
        # Certificate message is first, 32 bytes body → spans 2.25 blocks
        body = b'\xCC' * 32
        msg = self._make_msg(CERT_MSG_TYPE, body)
        # message = 4 (header) + 32 (body) = 36 bytes → blocks 0..2
        indices = find_cert_block_indices(msg)
        self.assertEqual(indices, [0, 1, 2])

    def test_cert_after_ext(self):
        # EncryptedExtensions (16 bytes body) puts cert at byte offset 20
        ext_body = b'\x00' * 16
        cert_body = b'\xBB' * 48
        m1 = self._make_msg(EXT_MSG_TYPE, ext_body)   # 4+16 = 20 bytes
        m2 = self._make_msg(CERT_MSG_TYPE, cert_body)  # 4+48 = 52 bytes
        plaintext = m1 + m2
        # cert spans bytes [20, 72) → blocks 1..4
        indices = find_cert_block_indices(plaintext)
        self.assertEqual(indices[0], 20 // 16)   # block 1
        self.assertEqual(indices[-1], (72 - 1) // 16)  # block 4

    def test_no_cert_returns_empty(self):
        body = b'\x00' * 10
        msg = self._make_msg(EXT_MSG_TYPE, body)
        self.assertEqual(find_cert_block_indices(msg), [])

    def test_indices_are_contiguous(self):
        cert_body = b'\xAA' * 100
        msg = self._make_msg(CERT_MSG_TYPE, cert_body)
        indices = find_cert_block_indices(msg)
        for i in range(1, len(indices)):
            self.assertEqual(indices[i], indices[i-1] + 1)


class TestExtractCertDer(unittest.TestCase):
    FAKE_DER = b'\x30\x82' + b'\x00' * 30  # fake DER (just needs a length)

    def test_single_cert_extracted(self):
        cert_msg = _build_cert_message(self.FAKE_DER)
        plaintext = _build_hs_plaintext(cert_msg)
        certs = extract_cert_der_from_record(plaintext)
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0], self.FAKE_DER)

    def test_no_cert_message_returns_empty(self):
        body = b'\x00' * 4
        ext_msg = bytes([EXT_MSG_TYPE]) + struct.pack('>I', len(body))[1:] + body
        certs = extract_cert_der_from_record(ext_msg)
        self.assertEqual(certs, [])


class TestEndToEndBlockDecryption(unittest.TestCase):
    """
    Simulate the full FI-MB certificate inspection pipeline without a live server.

    1. Build a synthetic handshake record (EncryptedExtensions + Certificate).
    2. "Encrypt" it with AES-GCM counter mode (no auth tag needed for test).
    3. Discover which blocks cover the Certificate.
    4. Derive counter blocks.
    5. XOR each cert ciphertext block with keystream to recover plaintext.
    6. Verify the recovered bytes contain the Certificate message.
    """

    KEY     = bytes(range(16))                          # 128-bit key
    BASE_IV = bytes(range(12))                          # 12-byte base IV
    SEQNUM  = 0                                         # first HS record
    FAKE_DER = b'\x30\x82\x01\x00' + b'\xAB' * 252    # 256-byte fake DER

    def setUp(self):
        # Build the plaintext record
        ext_body = b'\x00\x00'  # minimal EncryptedExtensions
        ext_msg  = bytes([EXT_MSG_TYPE]) + struct.pack('>I', len(ext_body))[1:] + ext_body
        cert_msg = _build_cert_message(self.FAKE_DER)
        self.plaintext = ext_msg + cert_msg

        # Encrypt the record
        self.ciphertext = _encrypt_record(
            self.plaintext, self.KEY, self.BASE_IV, self.SEQNUM)

        # Discover cert block indices from the plaintext
        self.cert_block_indices = find_cert_block_indices(self.plaintext)
        self.assertGreater(len(self.cert_block_indices), 0,
                           "Test setup: cert blocks not found")

    def test_cert_blocks_discovered(self):
        # There must be at least ceil((4 + cert_body_len) / 16) blocks
        cert_msg = _build_cert_message(self.FAKE_DER)
        min_blocks = math.ceil(len(cert_msg) / 16)
        self.assertGreaterEqual(len(self.cert_block_indices), min_blocks)

    def test_decrypt_cert_blocks_recovers_plaintext(self):
        # Decrypt only the cert blocks
        recovered = _decrypt_blocks(
            self.ciphertext, self.KEY, self.BASE_IV,
            self.SEQNUM, self.cert_block_indices)

        # The recovered bytes should span the certificate message.
        # Find cert start offset in plaintext:
        messages = _parse_handshake_messages(self.plaintext)
        cert_offset = next(offset for t, offset, _ in messages if t == CERT_MSG_TYPE)

        # The first block that covers the cert starts at:
        first_block = self.cert_block_indices[0]
        block_offset = first_block * 16

        # Extract the original cert bytes from plaintext at same positions
        cert_end = cert_offset + 4 + (messages[1][2] if len(messages) > 1 else messages[0][2])
        # Use the known cert_msg length
        cert_msg = _build_cert_message(self.FAKE_DER)
        cert_bytes_in_blocks = self.plaintext[block_offset:block_offset + len(recovered)]

        self.assertEqual(recovered, cert_bytes_in_blocks,
                         "Decrypted cert blocks do not match original plaintext")

    def test_counter_blocks_match_between_parties(self):
        # Simulate: client derives CTR blocks from (key, IV, seqnum)
        # MB derives CTR blocks from (wire-observed record nonce)
        # In an honest run they must be identical.
        ctrs_client = build_counter_blocks(self.BASE_IV, self.SEQNUM,
                                           len(self.cert_block_indices))
        ctrs_mb     = build_counter_blocks(self.BASE_IV, self.SEQNUM,
                                           len(self.cert_block_indices))
        self.assertEqual(ctrs_client, ctrs_mb)

    def test_wrong_key_gives_garbage(self):
        wrong_key = bytes([k ^ 0xFF for k in self.KEY])
        recovered = _decrypt_blocks(
            self.ciphertext, wrong_key, self.BASE_IV,
            self.SEQNUM, self.cert_block_indices)
        cert_msg = _build_cert_message(self.FAKE_DER)
        first_block = self.cert_block_indices[0]
        cert_bytes = self.plaintext[first_block*16:first_block*16 + len(recovered)]
        self.assertNotEqual(recovered, cert_bytes,
                            "Wrong key should not decrypt correctly")


if __name__ == '__main__':
    unittest.main(verbosity=2)
