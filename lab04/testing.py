import telnetlib
import json
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


b = (0).to_bytes(1, 'big')
data = 4 * b

print(data)
print(len(data))
print(len("&flag="))
print(len("&data="))

result = (16+9)%16 - 5
print(result)

print(len(b'flag{CBC_decrypt'))