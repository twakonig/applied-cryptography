#!/usr/bin/env python

from Crypto.Hash import SHA384, HMAC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        """Initialize the AEAD cipher.

        Keyword arguments:
        enc_key_len  -- byte length of the encryption key
        mac_key_len  -- byte length of the mac key
        key          -- key bytes
        """

        self.enc_key_len = 32
        self.mac_key_len = 24
        self.tag_len = 24

        # a correctly sized key must always be provided by the caller
        if not len(key) == self.mac_key_len + self.enc_key_len:
            raise ValueError("Bad key len")

        self.mac_key = key[:self.mac_key_len]
        self.enc_key = key[self.mac_key_len:]

        self.block_len = 16

    def _add_pt_padding(self, pt: bytes):
        """Return padded plaintext"""
        padding_len = self.block_len - len(pt) % self.block_len
        return pt + bytes([padding_len]) * padding_len

    def _remove_pt_padding(self, pt: bytes):
        """Return unpadded plaintext"""
        last_byte = pt[-1]
        if not last_byte in range(1, self.block_len + 1):
            raise ValueError("Bad decryption")
        return pt[:-last_byte]
        
    # def encrypt(self, pt: bytes, add_data: bytes = b'', iv: bytes = None):
    #     """Compute ciphertext and MAC tag.

    #     Keyword arguments:
    #     pt       -- plaintext
    #     add_data -- additional data
    #     iv       -- initialization vector
    #     """
    #     if iv is None:
    #         # Choose random IV.
    #         iv = get_random_bytes(self.block_len)

    #     cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
    #     ct = cipher.encrypt(self._add_pt_padding(pt))

    #     ad_len = (8 * len(add_data)).to_bytes(8, 'big').hex()

    #     # compute HMAC tag
    #     t = HMAC.new(self.mac_key, digestmod=SHA384)
    #     t.update(add_data + iv + ct + bytes.fromhex(ad_len))

    #     tag = t.digest()[:self.tag_len]

    #     return (iv + ct) + tag

    def decrypt(self, ct: bytes, add_data: bytes = b''):
        """Verify MAC tag and decrypt ciphertext.

        Keyword arguments:
        ct       -- ciphertext
        add_data -- additional data
        """

        iv = ct[:self.block_len]
        ctxt = ct[self.block_len:-self.tag_len]
        tag = ct[-self.tag_len:]

        # verify tag
        ad_len = (8 * len(add_data)).to_bytes(8, 'big').hex()
        t = HMAC.new(self.mac_key, digestmod=SHA384)
        t.update(add_data + iv + ctxt + bytes.fromhex(ad_len))
        tag_2 = t.digest()[:self.tag_len]

        if not tag_2 == tag:
            raise ValueError("Bad MAC")

        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ctxt)

        return self._remove_pt_padding(pt)


def main():
    key = bytes.fromhex('41206c6f6e6720726561642061626f75742073797374656d64206973207768617420796f75206e65656420616674657220746865206c6162')
    ct = bytes.fromhex('bb74c7b9634a382df5a22e0b744c6fda63583e0bf0e375a8a5ed1a332b9e0f78aab42a19af61745e4d30c3d04eeee23a7c17fc97d442738ef5fa69ea438b21e1b07fb71b37b52385d0e577c3b0c2da29fb7ae10060aa1f4b486f1d8e27cca8ab7df30af4ad0db52e')
    ad = bytes.fromhex('')

    dec = CBC_HMAC(16, 16, key).decrypt(ct, ad)
    print(dec.decode('utf-8'))

if __name__ == "__main__":
    main()
