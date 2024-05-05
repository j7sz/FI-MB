import sys
sys.path.insert(0, "./tlslite-ng-0.8.0-alpha40")
import os
from socket import *
import binascii
from dnslib import DNSRecord,DNSQuestion
from tlslite import TLSConnection, HandshakeSettings
from tlslite.constants import *
import time
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes) 


def tls_connect_to():
    oursettings = HandshakeSettings()
    oursettings.versions = [(3,4)]
    oursettings.cipherNames = ["aes128gcm"]
    oursettings.eccCurves = ["secp256r1"]
    oursettings.keyShares = ["secp256r1"]
    oursettings.usePaddingExtension = False

    try:
        sock2 = socket(AF_INET, SOCK_STREAM)
        # sock2.connect(('104.18.32.7', 443))
        # sock2.settimeout(2)
        sock2.connect(('1.1.1.1', 853))
        tlsconn2 = TLSConnection(sock2)
        tlsconn2.handshakeClientCert(settings=oursettings, print_handshake = False)
        msg = b"GET /questions/21153262/sending-html-through-python-socket-server HTTP/1.1\r\nHost: stackoverflow.com\r\n\r\n"
        tlsconn2.send(msg)

    except Exception as e:
        print("wtf", e)

    # response = tlsconn2.recv(4096)
    # print(response)
    return tlsconn2

if __name__=='__main__':
    a= tls_connect_to()
    print("====================================")
    c_ap_key = a._recordLayer._writeState.encContext.key
    c_ap_iv = a._recordLayer._writeState.fixedNonce
    print('Client Key', c_ap_key.hex())
    print('Client IV', c_ap_iv.hex())
    pt = a._recordLayer.plaintextMessage
    for i in pt:
        print("Plaintext:", i.hex())
    ct = a._recordLayer.ciphertextMessage
    for i in ct:
        print("Cipher:", i.write().hex())
