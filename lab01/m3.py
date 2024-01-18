# msg is bytes object, key is bytes object
def xor(msg, key):
    out = b''
    # b is bytes object -> b[i] is integer
    for i in range(len(msg)):
        enc = bytes([msg[i] ^ key[i]])
        out += enc
    return out

# msg is string, hex encoded key
def encrypt(msg, key):
    bkey = bytes.fromhex(key)
    bmsg = str.encode(msg)
    c = xor(bmsg, bkey)
    return c

msg = 'Pay no mind to the distant thunder, Beauty fills his head with wonder, boy'
key = 'bca914890bc40728b3cf7d6b5298292d369745a2592ad06ffac1f03f04b671538fdbcff6bd9fe1f086863851d2a31a69743b0452fd87a993f489f3454bbe1cab4510ccb979013277a7bf'
cipher = encrypt(msg, key)
print(cipher.hex())