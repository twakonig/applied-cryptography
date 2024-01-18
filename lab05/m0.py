from Crypto.Hash import SHA1, SHA256, HMAC, MD5
from Crypto.Protocol.KDF import scrypt


# Salt is 20 bytes
def onion(pw, salt, secret):
    # implement facebook onion
    md5 = MD5.new()
    md5.update(pw)
    h1 = md5.digest()

    hmac_sha1 = HMAC.new(salt, digestmod=SHA1)
    hmac_sha1.update(h1)
    h2 = hmac_sha1.digest()

    hmac_sha256 = HMAC.new(secret, digestmod=SHA256)
    hmac_sha256.update(h2)
    h3 = hmac_sha256.digest()

    h4 = scrypt(h3, salt, 64, N=2**10, r=32, p=2)

    hmac2_sha256 = HMAC.new(salt, digestmod=SHA256)
    hmac2_sha256.update(h4)
    h5 = hmac2_sha256.hexdigest()

    return h5



def main():
    # given parameters
    PW = '6f6e696f6e732061726520736d656c6c79'
    SECRET = '6275742061726520617765736f6d6520f09f988b'
    SALT = '696e2061206e69636520736f6666726974746f21'

    # onion hash of pw
    hash = onion(bytes.fromhex(PW), bytes.fromhex(SALT), bytes.fromhex(SECRET))
    print(hash)


if __name__ == "__main__":
    main()