"""
Certificate block finder for TLS 1.3 handshake inspection.

Given the DECRYPTED payload of a TLS 1.3 server handshake record, this
module locates the Certificate message and returns which 16-byte AES-GCM
blocks (by index within that record's ciphertext) contain it.

Those block indices are then fed into the MPC program: the client supplies
the server handshake key and the per-block counter values, the MB supplies
the same counter values it observed on the wire, and the MPC computes the
AES keystream for only those blocks — revealing just the certificate.

TLS 1.3 server handshake record layout (after AEAD decryption):
  [ EncryptedExtensions (0x08) | Certificate (0x0B) |
    CertificateVerify (0x0F) | Finished (0x14) | inner_content_type (1B) ]

Each handshake message:
  HandshakeType  (1 byte)
  Length         (3 bytes, big-endian)
  Body           (Length bytes)

Certificate body (RFC 8446 §4.4.2):
  certificate_request_context  (1-byte length-prefixed)
  certificate_list             (3-byte length-prefixed list of CertificateEntry)
    CertificateEntry:
      cert_data   (3-byte length-prefixed DER bytes)
      extensions  (2-byte length-prefixed)
"""

import math
import struct


CERT_MSG_TYPE        = 0x0B   # TLS handshake Certificate
EXT_MSG_TYPE         = 0x08   # EncryptedExtensions
CERT_VERIFY_MSG_TYPE = 0x0F
FINISHED_MSG_TYPE    = 0x14
INNER_CONTENT_TYPE   = 0x16   # last byte of TLS 1.3 decrypted record (handshake)


def _parse_handshake_messages(plaintext: bytes) -> list:
    """
    Parse the sequence of TLS handshake messages from a decrypted record.

    Returns a list of (msg_type, offset, length) tuples where offset points
    to the start of the 4-byte message header.
    The trailing inner-content-type byte is ignored.
    """
    messages = []
    i = 0
    body = plaintext  # already de-padded by recordlayer._tls13_de_pad
    while i + 4 <= len(body):
        msg_type = body[i]
        msg_len  = int.from_bytes(body[i+1:i+4], 'big')
        messages.append((msg_type, i, msg_len))
        i += 4 + msg_len
    return messages


def find_cert_message_offset(hs_plaintext: bytes) -> int:
    """
    Return the byte offset (within the decrypted record) of the Certificate
    handshake message's 4-byte header, or None if not found.
    """
    messages = _parse_handshake_messages(hs_plaintext)
    for msg_type, offset, _ in messages:
        if msg_type == CERT_MSG_TYPE:
            return offset
    return None


def find_cert_block_indices(hs_plaintext: bytes, block_size: int = 16) -> list:
    """
    Return the AES-GCM block indices (0-based within the encrypted record)
    that span the Certificate handshake message.

    The index i maps to ciphertext bytes [i*16 : (i+1)*16] and to counter
    block CTR_i = INC_32^(i+1)(J_0) in the AES-GCM stream.
    """
    messages = _parse_handshake_messages(hs_plaintext)
    for msg_type, offset, msg_len in messages:
        if msg_type == CERT_MSG_TYPE:
            cert_start = offset
            cert_end   = offset + 4 + msg_len
            first_block = cert_start  // block_size
            last_block  = (cert_end - 1) // block_size
            return list(range(first_block, last_block + 1))
    return []


def parse_certificate_der(cert_der: bytes) -> dict:
    """
    Extract high-level fields from a DER-encoded X.509 certificate for
    crypto inventory purposes.

    Returns a dict with keys: subject, issuer, not_before, not_after,
    sig_algorithm, pub_key_algorithm, pub_key_size_bits.

    Parsing is done with the cryptography library when available; falls back
    to raw field detection otherwise.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        pub_key = cert.public_key()
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
            if isinstance(pub_key, rsa.RSAPublicKey):
                pk_algo = "RSA"
                pk_size = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pk_algo = f"EC ({pub_key.curve.name})"
                pk_size = pub_key.key_size
            else:
                pk_algo = type(pub_key).__name__
                pk_size = None
        except Exception:
            pk_algo, pk_size = "unknown", None

        return {
            "subject":           cert.subject.rfc4514_string(),
            "issuer":            cert.issuer.rfc4514_string(),
            "not_before":        cert.not_valid_before_utc.isoformat(),
            "not_after":         cert.not_valid_after_utc.isoformat(),
            "sig_algorithm":     cert.signature_algorithm_oid.dotted_string,
            "pub_key_algorithm": pk_algo,
            "pub_key_size_bits": pk_size,
        }
    except ImportError:
        return {"raw_der_hex": cert_der[:32].hex() + "...", "note": "install cryptography to parse"}


def extract_cert_der_from_record(hs_plaintext: bytes) -> list:
    """
    Parse the Certificate handshake message and return a list of raw DER
    bytes for each certificate in the chain (leaf first).
    """
    messages = _parse_handshake_messages(hs_plaintext)
    for msg_type, offset, msg_len in messages:
        if msg_type != CERT_MSG_TYPE:
            continue
        body = hs_plaintext[offset + 4: offset + 4 + msg_len]
        idx = 0
        # certificate_request_context (1-byte length prefix)
        ctx_len = body[idx]; idx += 1 + ctx_len
        # certificate_list (3-byte length prefix)
        list_len = int.from_bytes(body[idx:idx+3], 'big'); idx += 3
        end = idx + list_len
        certs = []
        while idx < end:
            cert_len = int.from_bytes(body[idx:idx+3], 'big'); idx += 3
            certs.append(bytes(body[idx:idx+cert_len]));       idx += cert_len
            ext_len  = int.from_bytes(body[idx:idx+2], 'big'); idx += 2 + ext_len
        return certs
    return []


if __name__ == '__main__':
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tls-test'))
    from tls_hs_extract import tls_hs_connect

    conn = tls_hs_connect()

    print(f"Captured {len(conn.hs_decrypted_records)} decrypted handshake records.")
    for i, rec in enumerate(conn.hs_decrypted_records):
        indices = find_cert_block_indices(rec)
        if indices:
            print(f"\nRecord {i}: Certificate found in AES-GCM blocks {indices}")
            certs = extract_cert_der_from_record(rec)
            print(f"  Chain length: {len(certs)} certificate(s)")
            for j, der in enumerate(certs):
                info = parse_certificate_der(der)
                print(f"  Cert {j}:")
                for k, v in info.items():
                    print(f"    {k}: {v}")
            break
    else:
        print("No Certificate message found in handshake records.")
