from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad

class StrangeCBC():
    def __init__(self, key: bytes, iv: bytes = None, block_length: int = 16):
        """Initialize the CBC cipher.
        """

        if iv is None:
            # Pick a random IV
            iv = get_random_bytes(block_length)
            pass

        self.iv = iv
        self.key = key
        self.block_length = block_length
        self.n = 1336
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def xor(self, A, B):
        return bytes([a ^ b for (a, b) in zip(A, B)])

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CBC mode:

        C_i = E_k(P_i xor C_(i-1) xor 1336)
        C_0 = IV

        Uses IV and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext, starting from block 1 (do not include the IV)
        """
        # convert 1336
        num = self.n.to_bytes(self.block_length, 'big')

        # process plaintext (pad)
        padded_pt = pad(plaintext, self.block_length)
        C_prev = self.iv

        msg = b''
        ciphertext = b''

        for i in range(0, len(padded_pt), self.block_length):
            P_i = padded_pt[i : i+self.block_length]
            C_minus = C_prev
            temp = self.xor(P_i, num)
            msg = self.xor(temp, C_minus)
            C_prev = self.cipher.encrypt(msg)
            ciphertext += C_prev

        print('length ciphertext', len(ciphertext))
        print('ciphertext', ciphertext)
        print('plain enc', plaintext)
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CBC mode.

        Uses IV and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """
        # convert 1336
        num = self.n.to_bytes(self.block_length, 'big')

        # previous ciphertext block
        C_minus = self.iv

        plaintext = b''

        print('ciphert dec', ciphertext)
        for i in range(0, len(ciphertext), self.block_length):
            msg_i = self.cipher.decrypt(ciphertext[i : i + self.block_length])
            temp = self.xor(msg_i, num)
            P_i = self.xor(temp, C_minus)
            plaintext += P_i
            C_minus = ciphertext[i : i + self.block_length]

        print('length plaintext', len(plaintext))
       

        plaintext = unpad(plaintext, self.block_length)
        print('plaintext', plaintext)

        return plaintext

def main():
    cipher = StrangeCBC(get_random_bytes(16))

    # Block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    # Non-block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    key = bytes.fromhex("5f697180e158141c4e4bdcdc897c549a")
    iv  = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")
    ct = bytes.fromhex(
            "e7fb4360a175ea07a2d11c4baa8e058d57f52def4c9c5ab"
            "91d7097a065d41a6e527db4f5722e139e8afdcf2b229588"
            "3fd46234ff7b62ad365d1db13bb249721b")
    pt = StrangeCBC(key, iv=iv).decrypt(ct)
    print(pt.decode())
    print("flag{" + SHA1.new(pt).digest().hex() + "}")

if __name__ == "__main__":
    main()
