from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad

def xor(A, B):
    return bytes([a ^ b for (a, b) in zip(A, B)])


plaintext = b'hello lsdjfoaijnubiurefn oifdsj'
padded_pt = pad(plaintext, 16)


"""Encrypt the input plaintext using AES-128 in strange-CBC mode:

        C_i = E_k(P_i xor C_(i-1) xor 1336)
        C_0 = IV

        Uses IV and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext, starting from block 1 (do not include the IV)
        """
for i in range(0, len(padded_pt), 16):
    P_i = padded_pt[i : i+16]
    print(P_i)
    print(type(P_i))

xor_test = xor(padded_pt[0 : 16], padded_pt[16 : 32])

print((1).to_bytes(1, 'big'))
