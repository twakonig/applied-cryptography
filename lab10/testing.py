import math
from Crypto.PublicKey import RSA

RSA_KEYLEN = 1024  # 1024-bit modulus
RAND_LEN = 256  # 256-bit of randomness for masking
P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8

key = RSA.generate(RSA_KEYLEN)


ctxt_1 = b'\x00' * 8 + b'\x00' + b'\x01' * 7 + b'\x00' * 6 + b'\x01' * 2
print('ctxt_1: ', ctxt_1)
ctxt_1_int = int.from_bytes(ctxt_1, "big")


ctxt_2_int = (256 * ctxt_1_int) % key.n
ctxt_2 = ctxt_2_int.to_bytes(24, 'big')
print('ctxt_2: ', ctxt_2)

ctxt_2_int = (65536 * ctxt_1_int) % key.n
ctxt_2 = ctxt_2_int.to_bytes(24, 'big')
print('ctxt_2: ', ctxt_2)

ctxt_2_int = (2**32 * ctxt_1_int) % key.n
ctxt_2 = ctxt_2_int.to_bytes(24, 'big')
print('ctxt_2: ', ctxt_2)

print(2**1013)
print(2**1014)
