#!/usr/bin/python3
"""
TLS 1.3 handshake key and record extractor for certificate inspection.

In TLS 1.3 the server's Certificate, CertificateVerify, and Finished
messages are all encrypted with the server handshake traffic key — a key
derived from the ECDH key exchange that the client knows but the MB does
not.  This module captures:

  - The server handshake traffic key and IV (from the client's key schedule)
  - Every encrypted handshake record as seen on the wire
  - Every decrypted handshake record payload (for client-side block discovery)

The MB observes the same encrypted records on the wire and can supply them
back as inputs to the MPC protocol so both parties' counter blocks can be
cross-checked before the keystream is computed.
"""

import sys
sys.path.insert(0, "../tls-test/tlslite-ng-0.8.0-alpha40")

from socket import socket, AF_INET, SOCK_STREAM
from tlslite import TLSConnection, HandshakeSettings


class HandshakeCaptureMixin:
    """Thin wrapper around TLSConnection that exposes handshake state."""

    @property
    def server_hs_key(self) -> bytes:
        state = self._recordLayer._serverHandshakeState
        if state is None or state.encContext is None:
            raise RuntimeError("Handshake state not captured; call connect() first.")
        return bytes(state.encContext.key)

    @property
    def server_hs_iv(self) -> bytes:
        state = self._recordLayer._serverHandshakeState
        if state is None:
            raise RuntimeError("Handshake state not captured; call connect() first.")
        return bytes(state.fixedNonce)

    @property
    def hs_encrypted_records(self) -> list:
        """Encrypted handshake records in wire order (what the MB sees)."""
        return self._recordLayer.hsEncryptedRecords

    @property
    def hs_decrypted_records(self) -> list:
        """Decrypted handshake record payloads in wire order (client-only view)."""
        return self._recordLayer.hsDecryptedRecords


class InspectableTLSConnection(HandshakeCaptureMixin, TLSConnection):
    pass


def tls_hs_connect(host: str = '1.1.1.1', port: int = 853) -> InspectableTLSConnection:
    """
    Establish a TLS 1.3 / AES-128-GCM connection and return the connection
    object with captured handshake state.
    """
    settings = HandshakeSettings()
    settings.versions = [(3, 4)]
    settings.cipherNames = ["aes128gcm"]
    settings.eccCurves = ["secp256r1"]
    settings.keyShares = ["secp256r1"]
    settings.usePaddingExtension = False

    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((host, port))
    conn = InspectableTLSConnection(sock)
    conn.handshakeClientCert(settings=settings)
    return conn


if __name__ == '__main__':
    conn = tls_hs_connect()
    print("=== Server Handshake Traffic Key ===")
    print("Key:", conn.server_hs_key.hex())
    print("IV: ", conn.server_hs_iv.hex())

    print(f"\n=== Encrypted Handshake Records ({len(conn.hs_encrypted_records)} total) ===")
    for i, rec in enumerate(conn.hs_encrypted_records):
        print(f"  Record {i}: {len(rec)} bytes  [{rec[:8].hex()}...]")

    print(f"\n=== Decrypted Handshake Records ({len(conn.hs_decrypted_records)} total) ===")
    for i, rec in enumerate(conn.hs_decrypted_records):
        print(f"  Record {i}: {len(rec)} bytes  [{rec[:8].hex()}...]")

    print("\n=== Application Traffic Key (for reference) ===")
    print("Key:", conn._recordLayer._writeState.encContext.key.hex())
    print("IV: ", conn._recordLayer._writeState.fixedNonce.hex())
