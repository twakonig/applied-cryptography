#!/usr/bin/env python3

"""
This is a simple client implementation based on telnetlib that can help you connect to the remote server.

Taken from https://cryptohack.org/challenges/introduction/
"""

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50220

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

# encryption requests to encrypt msg
# msg.encode() is equivalent to b'oidjfoijdfoi' (returns bytes object)
msg = "flag, please!"
padded_msg = pad(msg.encode(), 16)

request = {
    "command": "encrypt",
    "prepend_pad": padded_msg.hex()
}
json_send(request)
response = json_recv()
#print(response)
c = response.get('res')
print(c)

encrypted_msg = bytes.fromhex(c)[:16]

# solve request to trieve flag
request = {
    "command": "solve",
    "ciphertext": encrypted_msg.hex()
}
json_send(request)
response = json_recv()
print(response)
