import os
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import binascii

import math
from implementing_aes import aes_encryption

import time


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
    # print("The extracted key materials", temp)
    cipher = GCTR_xor(P, temp)
    # print("The resulting ciphers", cipher)
    # print("Converting to hex string", bhex2hexstring(cipher))

    return C, temp

def jason_aes_gcm_extract(P, K, IV):
    len_IV = len(IV) * 8
    if len_IV == 96: #We are running this...
        J_0 = IV + b'\x00\x00\x00\x01'
    else:    
        H = aes_encryption(b'\x00' * (128 // 8), K) # Compute H1 on input 0000000000 and K
        s = 128 * math.ceil(len_IV / 128) - len_IV
        O_s_64 = b'\x00' * ((s + 64) // 8)
        len_IV_64 = int.to_bytes(len_IV, 8, 'big')
        J_0 = GHASH(H, IV + O_s_64 + len_IV_64) 

    key_materials = GCTR_extract(K, INC_32(J_0), P)

    return key_materials

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
    # print("The extracted key materials", temp)
    cipher = GCTR_xor(P, temp)
    # print("The resulting ciphers", cipher)
    # print("Converting to hex string", bhex2hexstring(cipher))

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

def Ori_AES_GCM_Enc(plaintext, associated_data, iv):
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext, associated_data)
    return ct




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

def tohex(val, nbits=128):
  return hex((val + (1 << nbits)) % (1 << nbits))

if __name__ == "__main__":

    # NIST Special Publication 800-38D

    # NIST test vector 1
    # key = bytes.fromhex('11754cd72aec309bf52f7687212e8957')
    # iv = bytes.fromhex('3c819d9a9bed087615030b65')

    # PText = "abcdefghabcdefgh"
    # hex_PText = string2hex(PText)
    # plaintext = bytes.fromhex(hex_PText)
    # print("Input text", hex_PText)
    # associated_data = bytes.fromhex('')
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

    key = bytes.fromhex('de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc')
    iv = bytes.fromhex('bb007956f474b25de902432f')
    # PText = "ping"
    # hex_PText = string2hex(PText)
    hex_PText = '70696e6717'                    # Client Data: 4bytes, Record Type: 1 byte
    plaintext = bytes.fromhex(hex_PText)
    print("Input text", hex_PText)
    associated_data = bytes.fromhex('1703030015')   # This is record header
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

    key = bytes.fromhex('de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc')
    iv = bytes.fromhex('bb007956f474b25de902432f')
    # PText = "ping"
    # hex_PText = string2hex(PText)
    hex_PText = '70 69 6e 67 17'                    # Client Data: 4bytes, Record Type: 1 byte
    plaintext = bytes.fromhex(hex_PText)
    print("Input text", hex_PText)
    associated_data = bytes.fromhex('1703030015')   # This is record header
    tag_length = 128
    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Plaintext :", hex_PText)
    print("Ciphertext:", bhex2hexstring(ciphertext))
    print("Auth Tag", bhex2hexstring(auth_tag), auth_tag)

    print(".... running in pieces.....")

    p1 = bytes.fromhex("70 69 6e 67 17")
    c1, e1 = jason_aes_gcm_encrypt(p1, key, iv, associated_data, tag_length)
    print("Trying to extract keying materials........")
    index = 0
    cipher = jason_GCTR_xor(p1, e1, index)
    print("Ori cipher", bhex2hexstring(c1))
    print("The resulting cipher at block", index, ":", bhex2hexstring(cipher))

    t = aes_gcm_authenticated_decryption(key, iv, auth_tag, associated_data, c1)
    print(t)

  # ============================= Jason test case 3 ========================================================
    print("========= case 3 ===========")


    key = bytes.fromhex('b3114ab03eda089383af182f2ec50a17')
    iv = bytes.fromhex('752ed29b698414fc525ea027')
    PText = "GET /questions/21153262/sending-html-through-python-socket-server HTTP/1.1\r\nHost: stackoverflow.com\r\n\r\n"
    hex_PText = string2hex(PText)
    # hex_PText = '00207cd2010000010000000000000377777706676f6f676c6503636f6d0000010001'                    # Client Data: 4bytes, Record Type: 1 byte
    # hex_PText = '474554202f7175657374696f6e732f32313135333236322f73656e64696e672d68746d6c2d7468726f7567682d707974686f6e2d736f636b65742d73657276657220485454502f312e310d0a486f73743a20737461636b6f766572666c6f772e636f6d0d0a0d0aee418225e3d956069bd21679152522c2'
    plaintext = bytes.fromhex(hex_PText)
    print("Input text", hex_PText)
    associated_data = bytes.fromhex('1703030078')   # This is record header
    tag_length = 128
    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Plaintext :", hex_PText)
    print("Ciphertext:", bhex2hexstring(ciphertext))
    print("Auth Tag", bhex2hexstring(auth_tag))

    print("========")
    start_time = time.time()
    for i in range(10):
        e = jason_aes_gcm_extract(plaintext, key, iv)
    print("Time taken (10 times):", time.time() - start_time)
    print("The keying materials:", bhex2hexstring(e[0]))
    # print("Selecting blocks....", bhex2hexstring(c[0:16]))
    #test_c = bytes.fromhex('34e7c5df0af10cc9a6355ac3784850c1e6')
    index = 0
    block_text = jason_GCTR_xor(ciphertext, e, index)
    l = len(ciphertext)
    i = 16 * index
    print("Ori additional block:", bhex2hexstring(ciphertext[i:i+16]))
    print("The resulting block:", bhex2hexstring(block_text))
    print("In plain:", block_text)

    # The following iv is for plaintext_block 1
    iv_2 = b"u.\xd2\x9bi\x84\x14\xfcR^\xa0'\x00\x00\x00\x02"
    print("Original IV:", bhex2hexstring(iv), "and during encryption IV_2:", bhex2hexstring(iv_2))
    
    #The following big int is for MPC (as it stores input/output as int)
    neg_int = -49647282631028740792246021233847733757
    print( tohex(neg_int))

    print("==============Case 4==================")
    key = bytes.fromhex('d8cbda2f884ae7e67a9dcad76c92e95a')
    iv = bytes.fromhex('c02e1eaafb0c6a4de9e3f35e')
    hex_PText = '474554202f7175657374696f6e732f32313135333236322f73656e64696e672d68746d6c2d7468726f7567682d707974686f6e2d736f636b65742d73657276657220485454502f312e310d0a486f73743a20737461636b6f766572666c6f772e636f6d0d0a0d0a'
    plaintext = bytes.fromhex(hex_PText) 
    plaintext += bytes([23]) #[23] bytes indicate the msg for application
    print("Input text", hex_PText)
    associated_data = bytes.fromhex('17030300') + bytes([len(plaintext)+16])   # This is record header
    tag_length = 128
    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)
    print("Plaintext :", hex_PText)
    print("Ciphertext:", bhex2hexstring(ciphertext))
    print("Auth Tag", bhex2hexstring(auth_tag))

    # 1da35cddef8addf1a86055c3d682b9bd62c169614b0e9f70de5ec7e5409ad33761656fbac6b1c68d972e75edaa27818614f08e088d78b2517efd4a4cbe4e3e68005658f068d8c04b3bfd88e82410b8809adeefadcdbde966ba8c18a9e38651a6d0bcfac2f2841aa2
    # 97f03a168b41e36735bc440c41f12a40

    