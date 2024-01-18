#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from passlib.hash import argon2

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50501

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


def main():


    request = {
        "command": "password"
    }
    json_send(request)
    response = json_recv()
    pw = response['res']

    print(pw)
    h = argon2.hash(bytes.fromhex(pw))
    print(h)
    print(type(h))

    request = {
        "command": "guess",
        "guess": h
    }
    json_send(request)
    response = json_recv()
    print(response)

    return
            

if __name__ == "__main__":
    main()