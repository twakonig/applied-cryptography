from typing import Tuple
import secrets
import math
from Crypto.PublicKey import RSA
from Crypto.Hash import SHAKE256


RSA_KEYLEN = 1024  # 1024-bit modulus, 128 bytes
RAND_LEN = 256  # 256-bit of randomness for masking, 32 bytes
P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8  # = 95 bytes = 760 bits


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def RSA_pad_encrypt(e: int, N: int, ptxt: bytes) -> Tuple[bytes, int]:
    print('-->ENCRYPTION')
    if len(ptxt) >= P_LEN:
        raise ValueError("Message too long to encrypt")

    rand = secrets.token_bytes(RAND_LEN // 8)

    # We use SHAKE256 in order to implement a hash function with output size of our liking
    rand_hashed = SHAKE256.new(rand).read(P_LEN)

    # ptxt_padded has P_LEN bits
    ptxt_padded = b"\x00" * (P_LEN - len(ptxt) - 1) + b"\x01" + ptxt
    assert len(ptxt_padded) == P_LEN

    ptxt_masked = xor(rand_hashed, ptxt_padded)
    m = int.from_bytes(b'\x00' + rand + ptxt_masked, "big")
    # print('rand_bitLen: ', int.from_bytes(rand, byteorder='big').bit_length())
    print('encryption of padded message, c = m^e mod N: (with m_biLen = ', m.bit_length(), ')')
    print(pow(m, e, N).to_bytes(RSA_KEYLEN // 8, 'big'))

    return pow(m, e, N).to_bytes(RSA_KEYLEN // 8, 'big'), m.bit_length()


def RSA_decrypt_unpad(d: int, N: int, ctxt: bytes) -> bytes:
    print('--->DECRYPTION')
    # big M in pdf
    m = pow(int.from_bytes(ctxt, "big"), d, N).to_bytes(RSA_KEYLEN // 8, 'big')
    print('decryption of c_prime, c_prime = (m*s)^e mod N:')
    print('m[0] :', m[0])
    print(m)

    # CHECK 1
    if m[0] != 0:
        raise ValueError("Error: Decryption failed")

    # split conctenation into single parts
    rand = m[1:1+RAND_LEN//8]
    ptxt_masked = m[1+RAND_LEN//8:]

    rand_hashed = SHAKE256.new(rand).read(P_LEN)
    # unmask plaintext_padded
    ptxt_padded = xor(ptxt_masked, rand_hashed)

    for i, b in enumerate(ptxt_padded):
        # CHECK 2
        if b == 1 and all(ch == 0 for ch in ptxt_padded[:i]):
            return ptxt_padded[i+1:]
    else:
        raise ValueError("Eror: Decryption failed")


def ask_decryption_oracle(d, N, c_prime):
    try:
        msg = RSA_decrypt_unpad(d, N, c_prime)
        print('decrypted message: ', msg)
    except (KeyError, ValueError, TypeError) as e:
        return False
        # print("-------------------FAIL----------------------------")
        # print(f"Invalid parameters: {type(e).__name__} {e}")
    else:
        del msg
        # print("Nom, nom, nom... This plaintext tasted nice!")
        print("-------------------SUCCESS----------------------------")
        return True


def c_times_s_to_e(c_int, s, e, N):
    s_to_e = pow(s, e, N)
    c_prime = (c_int * s_to_e) % N
    c_prime = c_prime.to_bytes(RSA_KEYLEN // 8, 'big')
    print('c_prime for s = ', s, ':')
    print(c_prime)
    return c_prime


def main():

    # imitate server
    key = RSA.generate(RSA_KEYLEN)
    N = key.n
    e = key.e
    d = key.d

    # do encryption
    message = b"If you use textbook RSA I will find you and hunt you down (cit.)"
    c, m_bitLen = RSA_pad_encrypt(e, N, message)
    c_int = int.from_bytes(c, byteorder='big')

    # do decryption of ciphertext form oracle
    c_prime = c
    ask_decryption_oracle(d, N, c_prime)

    # decryption for s=1
    c_prime = c_times_s_to_e(c_int, 1, e, N)
    ask_decryption_oracle(d, N, c_prime)

    # first s that hit was in the range of 2**12
    B = 2 ** (RSA_KEYLEN - 8)
    for s in range(math.ceil(N/(3*B)), (N - 1)):
        c_prime = c_times_s_to_e(c_int, s, e, N)
        good_guess = ask_decryption_oracle(d, N, c_prime)
        if good_guess:
            break

    return


if __name__ == "__main__":
    main()
