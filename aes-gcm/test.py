import os
import math
import binascii
import time

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM

from implementing_aes import aes_encryption


def xor_bytes(bytes_a: bytes, bytes_b: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(bytes_a, bytes_b))


def MUL(X_bytes: bytes, Y_bytes: bytes) -> bytes:
    X = int.from_bytes(X_bytes, 'big')
    Y = int.from_bytes(Y_bytes, 'big')
    R = 0xe1 << 120
    Z_i, V_i = 0, Y
    for i in range(128):
        if (X >> (127 - i)) & 1:
            Z_i ^= V_i
        V_i = (V_i >> 1) ^ R if V_i & 1 else V_i >> 1
    return Z_i.to_bytes(16, 'big')


def GHASH(H: bytes, X: bytes) -> bytes:
    Y = b'\x00' * 16
    for i in range(len(X) // 16):
        Y = MUL(xor_bytes(Y, X[i*16:(i+1)*16]), H)
    return Y


def INC_32(Y_bytes: bytes) -> bytes:
    Y = int.from_bytes(Y_bytes, 'big')
    Y_inc = ((Y >> 32) << 32) ^ (((Y & 0xffffffff) + 1) & 0xffffffff)
    return Y_inc.to_bytes(16, 'big')


def _compute_J0(K: bytes, IV: bytes) -> bytes:
    len_IV = len(IV) * 8
    if len_IV == 96:
        return IV + b'\x00\x00\x00\x01'
    H = aes_encryption(b'\x00' * 16, K)
    s = 128 * math.ceil(len_IV / 128) - len_IV
    return GHASH(H, IV + b'\x00' * ((s + 64) // 8) + len_IV.to_bytes(8, 'big'))


def GCTR_extract(K: bytes, ICB: bytes, X: bytes) -> list:
    """Return AES keystream blocks e[i] = AES(K, CTR_i) for each counter position."""
    n = math.ceil(len(X) / 16)
    counters = [ICB]
    for _ in range(1, n):
        counters.append(INC_32(counters[-1]))
    return [aes_encryption(cb, K) for cb in counters]


def GCTR_xor(X: bytes, e: list) -> bytes:
    """XOR all plaintext/ciphertext blocks against pre-computed keystream blocks."""
    if not X:
        return b''
    return b''.join(xor_bytes(X[i*16:(i+1)*16], e[i]) for i in range(len(e)))


def jason_GCTR_xor(X: bytes, e: list, index: int) -> bytes:
    """Decrypt a single block at the given index using its keystream block."""
    return xor_bytes(X[index*16:(index+1)*16], e[index])


def GCTR(K: bytes, ICB: bytes, X: bytes) -> bytes:
    if not X:
        return b''
    return GCTR_xor(X, GCTR_extract(K, ICB, X))


def jason_aes_gcm_extract(P: bytes, K: bytes, IV: bytes) -> list:
    """Extract per-block AES-GCM keystreams without decrypting the full ciphertext."""
    J_0 = _compute_J0(K, IV)
    return GCTR_extract(K, INC_32(J_0), P)


def jason_aes_gcm_encrypt(P: bytes, K: bytes, IV: bytes, A: bytes, t: int):
    """Encrypt and return (ciphertext, keystream_blocks)."""
    J_0 = _compute_J0(K, IV)
    ICB = INC_32(J_0)
    e = GCTR_extract(K, ICB, P)
    C = GCTR_xor(P, e)
    return C, e


def aes_gcm_encrypt(P: bytes, K: bytes, IV: bytes, A: bytes, t: int):
    """Full AES-GCM authenticated encryption returning (ciphertext, auth_tag)."""
    H = aes_encryption(b'\x00' * 16, K)
    J_0 = _compute_J0(K, IV)
    C = GCTR(K, INC_32(J_0), P)
    len_C, len_A = len(C) * 8, len(A) * 8
    u = 128 * math.ceil(len_C / 128) - len_C
    v = 128 * math.ceil(len_A / 128) - len_A
    S = GHASH(H, A + b'\x00' * (v // 8) + C + b'\x00' * (u // 8)
              + len_A.to_bytes(8, 'big') + len_C.to_bytes(8, 'big'))
    T = GCTR(K, J_0, S)[:t // 8]
    return C, T


def aes_gcm_authenticated_decryption(key: bytes, iv: bytes, auth_tag: bytes,
                                      associated_data: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(AES(key), GCM(iv, auth_tag)).decryptor()
    dec.authenticate_additional_data(associated_data)
    return dec.update(ciphertext) + dec.finalize()


def ori_aes_encryption(plaintext: bytes, key: bytes, iv: bytes,
                        associated_data: bytes, tag_length: int):
    if iv is None:
        iv = os.urandom(16)
    enc = Cipher(AES(key), GCM(iv)).encryptor()
    enc.authenticate_additional_data(associated_data)
    C = enc.update(plaintext) + enc.finalize()
    return C, enc.tag


def bhex2hexstring(data: bytes) -> str:
    return binascii.hexlify(data).decode('utf-8')


def string2hex(s: str) -> str:
    return binascii.hexlify(s.encode('utf-8')).decode('utf-8')


def tohex(val: int, nbits: int = 128) -> str:
    return hex((val + (1 << nbits)) % (1 << nbits))


if __name__ == "__main__":

    # Test case 1: short "ping" message
    key = bytes.fromhex('de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc')
    iv  = bytes.fromhex('bb007956f474b25de902432f')
    plaintext       = bytes.fromhex('70696e6717')
    associated_data = bytes.fromhex('1703030015')
    tag_length = 128

    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Plaintext :", bhex2hexstring(plaintext))
    print("Ciphertext:", bhex2hexstring(ciphertext))
    print("Auth Tag  :", bhex2hexstring(auth_tag))

    C, e = jason_aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Block 0 cipher:", bhex2hexstring(jason_GCTR_xor(plaintext, e, 0)))
    t = aes_gcm_authenticated_decryption(key, iv, auth_tag, associated_data, C)
    print("Decrypted:", t)

    # Test case 2: HTTP GET request
    print("\n=== HTTP GET test ===")
    key = bytes.fromhex('b3114ab03eda089383af182f2ec50a17')
    iv  = bytes.fromhex('752ed29b698414fc525ea027')
    plaintext = bytes.fromhex(string2hex(
        "GET /questions/21153262/sending-html-through-python-socket-server HTTP/1.1\r\n"
        "Host: stackoverflow.com\r\n\r\n"
    ))
    associated_data = bytes.fromhex('1703030078')
    tag_length = 128

    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Ciphertext:", bhex2hexstring(ciphertext))
    print("Auth Tag  :", bhex2hexstring(auth_tag))

    start_time = time.time()
    for _ in range(10):
        e = jason_aes_gcm_extract(plaintext, key, iv)
    print(f"Key extraction time (10x): {time.time() - start_time:.4f}s")
    print("Keying material block 0:", bhex2hexstring(e[0]))

    index = 0
    block_text = jason_GCTR_xor(ciphertext, e, index)
    print(f"Decrypted block {index}:", block_text)
    print(f"Negative int as hex: {tohex(-49647282631028740792246021233847733757)}")

    # Test case 3: HTTP GET with TLS record type byte
    print("\n=== Case 3 ===")
    key = bytes.fromhex('d8cbda2f884ae7e67a9dcad76c92e95a')
    iv  = bytes.fromhex('c02e1eaafb0c6a4de9e3f35e')
    plaintext = bytes.fromhex(
        '474554202f7175657374696f6e732f32313135333236322f73656e64696e67'
        '2d68746d6c2d7468726f7567682d707974686f6e2d736f636b65742d736572'
        '76657220485454502f312e310d0a486f73743a20737461636b6f766572666c'
        '6f772e636f6d0d0a0d0a'
    ) + bytes([23])
    associated_data = bytes.fromhex('17030300') + bytes([len(plaintext) + 16])
    tag_length = 128

    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Ciphertext:", bhex2hexstring(ciphertext))
    print("Auth Tag  :", bhex2hexstring(auth_tag))
