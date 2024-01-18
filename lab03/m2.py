#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50302

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

def xor(A, B):
    return bytes([a ^ b for (a, b) in zip(A, B)])

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

# --- intro request ---
num = (1337).to_bytes(16, 'big')
P_intro = pad(b'intro', 16)
P_flag = pad(b'flag', 16)

request = {
    "command" : "encrypted_command",
    "encrypted_command" : P_intro.hex()
}
json_send(request)

response = json_recv()
print(response)

# # --- intro request ---
# C_intro = '01f0ceb3dad5f9cd23293937c893e0ec'
# request = {
#     "command": "encrypted_command",
#     "encrypted_command" : C_intro
# }
# json_send(request)

# response = json_recv()
# print(response)

# # --- flag request ---
# num = int(1337).to_bytes(16, 'big')
# C_intro = bytes.fromhex(C_intro)
# P_intro = pad(b'intro', 16)

# # R is value outputted by blockcipher (AES(nonce||ctr))
# R = xor(xor(C_intro, P_intro), num)

# P_flag = pad(b'flag', 16)
# C_flag = xor(xor(R, P_flag), num)

# request = {
#     "command": "encrypted_command",
#     "encrypted_command" : C_flag.hex()
# }
# json_send(request)

# response = json_recv()
# print(response)

