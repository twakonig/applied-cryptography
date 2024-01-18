#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50340

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

def query(command, action, value):
    request = {
        "command": command,
        str(action): value
    }
    json_send(request)


def main():
    # --- decrypt request ---
    hello = pad(b'hello this is a weird oracle', 16).hex()
    print(hello)
    # if ask for same C_1 more than once
    value_error = pad(b'You cannot just reflect or repeat ct blocks.', 16)
    print(len(value_error))

    # lenght 160
    reuse_msg = 'edb236e2b4cfc1c2794f9c7265197c8b1b746585531a57b8c484ef40facd50304127d4b5e0b1e26d386c762d05dc6460793bcfdba4d4f4e25b0bf4f2945250d52d656ab17d65bd2e0a3e8f93c2b69d07'
    print(len(reuse_msg))
    # response is error (invalid padding). length = 128
    invalid_response = 'd801891b11563adc0b9208f38a09feff48f8d8ea53ba5f94519c60512510c598c118af97a5ec6dc877647c3e85fc28f1ee3878041e42892c732e9e54ecd53f09'
    print(len(invalid_response))

 
    ciphertext = b''
    value = False

    for i in range(300):
        ciphertext = (i).to_bytes(16, 'big')
        query('decrypt', 'ciphertext', ciphertext.hex())
        response = json_recv()
        #print(response)

        if len(response['res']) == 128:
            value = False
        else:
            value = True

        query('guess', 'guess', value)
        response = json_recv()
        print(response)

    request = {
        "command": 'flag'
    }
    json_send(request)
    response = json_recv()
    print(response)


if __name__ == "__main__":
    main()