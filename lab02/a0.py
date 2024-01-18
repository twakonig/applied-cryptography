# pkcs7 padding, input is string, final_len is int
def padding(input, final_len):
    out = bytes(input, 'utf-8')
    pad_len = final_len - len(input)
    for i in range(pad_len):
        out += (pad_len).to_bytes(1, 'big')
    return out


input = 'flag'
res = padding(input, 16)
# hexadecimal bytes representation
print(res.hex())
 