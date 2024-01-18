#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50303

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

# --- howto request ---
request = {
    "command": "howto"
}
json_send(request)

response = json_recv()
print(response)

# --- intro request ---
C_intro = '31a873bb9ec4424df0a77b1ade09c28b8b1a56b250f577b732f87a41cf9bb504'
print(len(C_intro))
print(type(C_intro))
print(len(bytes.fromhex(C_intro)))
print(type(bytes.fromhex(C_intro)))

request = {
    "command": "encrypted_command",
    "encrypted_command" : C_intro
}
json_send(request)

response = json_recv()
print(response)

# --- flag request ---
iv = bytes.fromhex(C_intro)[0:16]
num = (1336).to_bytes(16, 'big')
P_intro = pad(b'intro', 16)
C_intro = bytes.fromhex(C_intro)[16:]
P_flag = pad(b'flag', 16)

R = xor(xor(P_intro, iv), num)
iv_new = xor(xor(R, P_flag), num)

ciphertext = iv_new + C_intro

request = {
    "command": "encrypted_command",
    "encrypted_command" : ciphertext.hex()
}
json_send(request)

response = json_recv()
print(response)



