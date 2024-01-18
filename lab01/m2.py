# msg is bytes object
def xor(msg, key):
    out = b''
    # b is bytes object -> b[i] is integer
    for i in range(len(msg)):
        dec = bytes([msg[i] ^ key])
        out += dec
    return out


input = '210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002'
bytes_input = bytes.fromhex(input)
# iterate over all possibles keys (=bytes)
for i in range(256):
    print("key: ", i)
    flag = xor(bytes_input, i)
    print(flag.decode(encoding='utf-8'))

# flag @ key 103: Finally, someone let me out of my cage
