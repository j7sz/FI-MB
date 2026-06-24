#!/usr/bin/python3

import sys
sys.path.insert(0, "./tlslite-ng-0.8.0-alpha40")

from socket import socket, AF_INET, SOCK_STREAM
from tlslite import TLSConnection, HandshakeSettings


def tls_connect_to() -> TLSConnection:
    settings = HandshakeSettings()
    settings.versions = [(3, 4)]
    settings.cipherNames = ["aes128gcm"]
    settings.eccCurves = ["secp256r1"]
    settings.keyShares = ["secp256r1"]
    settings.usePaddingExtension = False

    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect(('1.1.1.1', 853))
    tlsconn = TLSConnection(sock)
    tlsconn.handshakeClientCert(settings=settings)
    msg = (b"GET /questions/21153262/sending-html-through-python-socket-server"
           b" HTTP/1.1\r\nHost: stackoverflow.com\r\n\r\n")
    tlsconn.send(msg)
    return tlsconn


if __name__ == '__main__':
    conn = tls_connect_to()
    print("====================================")
    c_ap_key = conn._recordLayer._writeState.encContext.key
    c_ap_iv  = conn._recordLayer._writeState.fixedNonce
    print('Client Key:', c_ap_key.hex())
    print('Client IV: ', c_ap_iv.hex())

    for pt in conn._recordLayer.plaintextMessage:
        print("Plaintext:", pt.hex())
    for ct in conn._recordLayer.ciphertextMessage:
        print("Cipher:   ", ct.write().hex())
