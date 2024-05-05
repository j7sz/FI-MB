import os
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM



import binascii

import math
from implementing_aes import aes_encryption


def xor_bytes(bytes_a: bytes, bytes_b: bytes) -> bytes:
    return bytes([a ^ b for (a, b) in zip(bytes_a, bytes_b)])


def MUL(X_bytes, Y_bytes):

    X = int.from_bytes(X_bytes, 'big')
    Y = int.from_bytes(Y_bytes, 'big')

    # Constant R defined for algorithm
    R = 0xe1 << 120

    # Step 1
    x = [1 if X & (1 << i) else 0 for i in range(127, -1, -1)]

    # Steps 2 and 3
    Z_i = 0
    V_i = Y
    for i in range(128):
        if x[i] == 0:
            Z_i_1 = Z_i
        else:
            Z_i_1 = Z_i ^ V_i

        if V_i % 2 == 0:
            V_i_1 = V_i >> 1
        else:
            V_i_1 = (V_i >> 1) ^ R

        Z_i = Z_i_1
        V_i = V_i_1

    # Step 4
    return Z_i.to_bytes(16, 'big')


def GHASH(H, X):

    # Input constraint: len(X) = 128m
    m = len(X) // 16

    # Step 1
    X_blocks = [X[i*16:(i+1)*16] for i in range(m)]

    # Step 2
    Y_0 = b'\x00' * 16

    # Step 3
    Y_i_1 = Y_0
    for i in range(m):
        X_i = X_blocks[i]
        Y_i = MUL(xor_bytes(Y_i_1, X_i), H)
        Y_i_1 = Y_i

    # Step 4
    return Y_i_1


def INC_32(Y_bytes):
    Y = int.from_bytes(Y_bytes, 'big')
    Y_inc = ((Y >> 32) << 32) ^ (((Y & 0xffffffff) + 1) & 0xffffffff)
    return Y_inc.to_bytes(16, 'big')


def GCTR(K, ICB, X):

    # Step 1
    if not X:
        return b''

    # Step 2
    n = math.ceil(len(X) / 16)

    # Step 3
    X_blocks = [X[i*16:(i+1)*16] for i in range(n)]   # This arrange input plaintext into block (16bytes)

    # Step 4
    CB = [ICB] # Initiate a list of IV

    # Step 5
    for i in range(1, n):  # Do IV++
        CB_i = INC_32(CB[i-1])
        CB.append(CB_i)

    # Steps 6 and 7
    Y_blocks = []
    for i in range(n):
        X_i = X_blocks[i]
        CB_i = CB[i]
        #Y_i = xor_bytes(X_i, aes_encryption(CB_i, K))    # C = P xor Aes(IV,K)
        e = aes_encryption(CB_i, K) # Based on our result, we wanna derive this 'key material'
        Y_i = xor_bytes(X_i, e) 
        Y_blocks.append(Y_i)

    # Step 8
    Y = b''.join(Y_blocks)

    # Step 9
    return Y

def GCTR_extract(K, ICB, X):
    n = math.ceil(len(X) / 16)
    CB = [ICB] # Initiate a list of IV

    for i in range(1, n):  # Do IV++
        CB_i = INC_32(CB[i-1])
        CB.append(CB_i)


    e= []
    for i in range(n):
        CB_i = CB[i]
        #Y_i = xor_bytes(X_i, aes_encryption(CB_i, K))    # C = P xor Aes(IV,K)
        e_i = aes_encryption(CB_i, K) # Based on our result, we wanna derive this 'key material'
        e.append(e_i)

    return e

def GCTR_xor(X, e):

    # Step 1
    if not X:
        return b''

    # Step 2
    n = math.ceil(len(X) / 16)

    # Step 3
    X_blocks = [X[i*16:(i+1)*16] for i in range(n)]   # This arrange input plaintext into block (16bytes)

    # Steps 6 and 7
    Y_blocks = []
    for i in range(n):
        X_i = X_blocks[i]
        #Y_i = xor_bytes(X_i, aes_encryption(CB_i, K))    # C = P xor Aes(IV,K)
        #e = aes_encryption(CB_i, K) # Based on our result, we wanna derive this 'key material'
        Y_i = xor_bytes(X_i, e[i]) 
        Y_blocks.append(Y_i)

    # Step 8
    Y = b''.join(Y_blocks)

    # Step 9
    return Y

def jason_GCTR_xor(X, e, index):

    # Step 1
    if not X:
        return b''

    # Step 2
    n = math.ceil(len(X) / 16)

    # Step 3
    X_blocks = [X[i*16:(i+1)*16] for i in range(n)]   # This arrange input plaintext into block (16bytes)

    Y = xor_bytes(X_blocks[index], e[index])

    # Step 9
    return Y

def jason_aes_gcm_encrypt(P, K, IV, A, t):

    # Step 1
    H = aes_encryption(b'\x00' * (128 // 8), K) # Compute H1 on input 0000000000 and K

    # Step 2
    len_IV = len(IV) * 8
    if len_IV == 96: #Most likely we will do this...
        J_0 = IV + b'\x00\x00\x00\x01'
    else: 
        s = 128 * math.ceil(len_IV / 128) - len_IV
        O_s_64 = b'\x00' * ((s + 64) // 8)
        len_IV_64 = int.to_bytes(len_IV, 8, 'big')
        J_0 = GHASH(H, IV + O_s_64 + len_IV_64) 

    # Step 3
    C = GCTR(K, INC_32(J_0), P) # Compute H2?
    temp = GCTR_extract(K, INC_32(J_0), P)
    print("The extracted key materials", temp)
    cipher = GCTR_xor(P, temp)
    print("The resulting ciphers", cipher)
    print("Converting to hex string", bhex2hexstring(cipher))

    return C, temp

def aes_gcm_encrypt(P, K, IV, A, t):

    # Step 1
    H = aes_encryption(b'\x00' * (128 // 8), K) # Compute H1 on input 0000000000 and K

    # Step 2
    len_IV = len(IV) * 8
    if len_IV == 96: #Most likely we will do this...
        J_0 = IV + b'\x00\x00\x00\x01'
    else: 
        s = 128 * math.ceil(len_IV / 128) - len_IV
        O_s_64 = b'\x00' * ((s + 64) // 8)
        len_IV_64 = int.to_bytes(len_IV, 8, 'big')
        J_0 = GHASH(H, IV + O_s_64 + len_IV_64) 

    # Step 3
    C = GCTR(K, INC_32(J_0), P) # Compute H2?
    temp = GCTR_extract(K, INC_32(J_0), P)
    print("The extracted key materials", temp)
    cipher = GCTR_xor(P, temp)
    print("The resulting ciphers", cipher)
    print("Converting to hex string", bhex2hexstring(cipher))

    # Step 4
    len_C, len_A = len(C) * 8, len(A) * 8
    u = 128 * math.ceil(len_C / 128) - len_C
    v = 128 * math.ceil(len_A / 128) - len_A

    # Step 5
    O_v = b'\x00' * (v // 8)
    O_u = b'\x00' * (u // 8)
    len_A_64 = int.to_bytes(len_A, 8, 'big')
    len_C_64 = int.to_bytes(len_C, 8, 'big')
    S = GHASH(H, A + O_v + C + O_u + len_A_64 + len_C_64)

    # Step 6
    T = GCTR(K, J_0, S)[:t // 8]  # Assumes tag length multiple of 8

    # Step 7
    return C, T

def aes_gcm_authenticated_decryption(key, iv, auth_tag, associated_data, ciphertext):
    aes_gcm_decryptor = Cipher(AES(key), GCM(iv, auth_tag)).decryptor()
    aes_gcm_decryptor.authenticate_additional_data(associated_data)
    recovered_plaintext = aes_gcm_decryptor.update(ciphertext) + aes_gcm_decryptor.finalize()
    return recovered_plaintext

def ori_aes_encryption(plaintext, key, iv, associated_data, tag_length):
    if iv == None:
        iv = os.urandom(16)
        print("new iv", iv)
    aes_gcm_encryptor = Cipher(AES(key), GCM(iv)).encryptor()
    aes_gcm_encryptor.authenticate_additional_data(associated_data)
    C = aes_gcm_encryptor.update(plaintext) + aes_gcm_encryptor.finalize()
    T = aes_gcm_encryptor.tag

    return C, T




def string2hex(input):
    hex_representation = binascii.hexlify(input.encode('utf-8')).decode('utf-8')
    return hex_representation

def bhex2hexstring(input):
    hex_string = binascii.hexlify(input).decode('utf-8')
    return hex_string

def xor_iv_with_count(iv, count):
    count = 4
    modified_iv = bytes(iv_byte ^ count for iv_byte in iv)
    return modified_iv


if __name__ == "__main__":

    # NIST Special Publication 800-38D

    # NIST test vector 1
    # key = bytearray.fromhex('11754cd72aec309bf52f7687212e8957')
    # iv = bytearray.fromhex('3c819d9a9bed087615030b65')

    # PText = "abcdefghabcdefgh"
    # hex_PText = string2hex(PText)
    # plaintext = bytearray.fromhex(hex_PText)
    # print("Input text", hex_PText)
    # associated_data = bytearray.fromhex('')
    # tag_length = 128

    # ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    # print("Plaintext :", hex_PText)
    # print("Ciphertext:", bhex2hexstring(ciphertext))
    # print("Auth Tag", bhex2hexstring(auth_tag))


    # c2, t2 = ori_aes_encryption(plaintext, key, iv, associated_data, tag_length)

    # recovered_plaintext = aes_gcm_authenticated_decryption(key, iv, auth_tag, associated_data, ciphertext)
    # recovered_plaintext2 = aes_gcm_authenticated_decryption(key, iv, t2, associated_data, c2)
    # print(recovered_plaintext, recovered_plaintext2, plaintext)

    # ============================= Jason test case ========================================================

    key = bytearray.fromhex('de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc')
    iv = bytearray.fromhex('bb007956f474b25de902432f')
    # PText = "ping"
    # hex_PText = string2hex(PText)
    hex_PText = '70696e6717'                    # Client Data: 4bytes, Record Type: 1 byte
    plaintext = bytearray.fromhex(hex_PText)
    print("Input text", hex_PText)
    associated_data = bytearray.fromhex('1703030015')   # This is record header
    tag_length = 128
    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Plaintext :", hex_PText)
    print("Ciphertext:", bhex2hexstring(ciphertext))
    print("Auth Tag", bhex2hexstring(auth_tag))

    print("====================")

    c1, e1 = jason_aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    p1 = plaintext
    cipher = GCTR_xor(p1, e1)
    print("The resulting ciphers", bhex2hexstring(cipher))


    # ============================= Jason test case 2 ========================================================
    print("=== Keying materials encryption ===")

    key = bytearray.fromhex('de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc')
    iv = bytearray.fromhex('bb007956f474b25de902432f')
    # PText = "ping"
    # hex_PText = string2hex(PText)
    hex_PText = '70 69 6e 67 17'                    # Client Data: 4bytes, Record Type: 1 byte
    plaintext = bytearray.fromhex(hex_PText)
    print("Input text", hex_PText)
    associated_data = bytearray.fromhex('1703030015')   # This is record header
    tag_length = 128
    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Plaintext :", hex_PText)
    print("Ciphertext:", bhex2hexstring(ciphertext))
    print("Auth Tag", bhex2hexstring(auth_tag))

    print(".... running in pieces.....")

    p1 = bytearray.fromhex("70 69 6e 67 17")
    c1, e1 = jason_aes_gcm_encrypt(p1, key, iv, associated_data, tag_length)
    print("Trying to extract keying materials........")
    index = 0
    cipher = jason_GCTR_xor(p1, e1, index)
    print("Ori cipher", bhex2hexstring(c1))
    print("The resulting cipher at block", index, ":", bhex2hexstring(cipher))


  # ============================= Jason test case 3 ========================================================
    print("========= case 3 ===========")


    key = bytearray.fromhex('81913c9c94f6feb9d8a441eabb69a0f3')
    iv = bytearray.fromhex('509037d33d3ceed8df046d8d')
    PText = "GET /questions/21153262/sending-html-through-python-socket-server HTTP/1.1\r\nHost: stackoverflow.com\r\n\r\n"
    hex_PText = string2hex(PText)
    # hex_PText = '00207cd2010000010000000000000377777706676f6f676c6503636f6d0000010001'                    # Client Data: 4bytes, Record Type: 1 byte
    plaintext = bytearray.fromhex(hex_PText)
    print("Input text", hex_PText)
    associated_data = bytearray.fromhex('1703030078')   # This is record header
    tag_length = 128
    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Plaintext :", hex_PText)
    print("Ciphertext:", bhex2hexstring(ciphertext))
    print("Auth Tag", bhex2hexstring(auth_tag))


    
