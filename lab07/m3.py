#!/usr/bin/env python

from Crypto.Hash import SHA256

...

class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        """Initialize the AEAD cipher.

        Keyword arguments:
        enc_key_len  -- byte length of the encryption key
        mac_key_len  -- byte length of the mac key
        key          -- key bytes
        """

        self.enc_key_len = 16
        self.mac_key_len = 16
        self.tag_len = 16

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


def main():
    aead = CBC_HMAC(16, 16, b''.join(bytes([i]) for i in range(32)))
    pt = b"Just plaintext\x02\x00"
    assert aead._remove_pt_padding(aead._add_pt_padding(pt)) == pt
    print(SHA256.new(data=aead._add_pt_padding(pt)).hexdigest())

if __name__ == "__main__":
    main()
