from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad


def xor(A, B):
    return bytes([a ^ b for (a, b) in zip(A, B)])

class StrangeCTR():
    def __init__(self, key: bytes, nonce : bytes = None, initial_value : int = 0, block_length: int = 16):
        """Initialize the CTR cipher.
        """

        if nonce is None:
            # Pick a random nonce
            nonce = get_random_bytes(block_length//2)

        self.nonce = nonce
        self.initial_value = initial_value
        self.key = key
        self.block_length = block_length
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.num_1337 = int(1337).to_bytes(self.block_length, 'big')

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CTR mode:

        C_i = E_k(N || c(i)) xor P_i xor 1337

        Uses nonce, counter initial value and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext
        """
        ciphertext = b''
        plaintext = pad(plaintext, self.block_length)

        # iterate over plaintext (and counter)
        for i in range(0, len(plaintext), self.block_length):
            ctr = i.to_bytes(self.block_length//2, 'big')
            P_i = plaintext[i : i + self.block_length]
            Enc_N_c = self.cipher.encrypt(self.nonce + ctr)
            C_i = xor(xor(Enc_N_c, P_i), self.num_1337)
            ciphertext += C_i

        return ciphertext


    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CTR mode.

        Uses nonce, counter initial value and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """

        plaintext = b''

        for i in range(0, len(ciphertext), self.block_length):
            ctr = i.to_bytes(self.block_length//2, 'big')
            C_i = ciphertext[i : i + self.block_length]
            Enc_N_c = self.cipher.encrypt(self.nonce + ctr)
            P_i = xor(xor(C_i, Enc_N_c), self.num_1337)
            plaintext += P_i

        plaintext = unpad(plaintext, self.block_length)

        return plaintext

def main():
    cipher = StrangeCTR(get_random_bytes(16))

    # Block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    # Non-block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

if __name__ == "__main__":
    main()
