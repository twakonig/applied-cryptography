#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50401

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
    # --- register ---
    # put 11 characters into 'username' field -> creates 48 bytes (= 3 blocks)
    username = "01234567891"
    # creates three more blocks that we later need as a token
    favourite_coffee = "username=lol&role=admin&favourite_coffee=tea"

    request = {
        "command": "register",
        "username": username,
        "favourite_coffee": favourite_coffee
    }
    json_send(request)
    response = json_recv()

    token = response['token']
    b_token = bytes.fromhex(token)
    admin_token = b_token[48:96]


    # --- login as admin ---
    request = {
        "command": "login",
        "token": admin_token.hex()
    }
    json_send(request)
    response = json_recv()
    print(response)


    # --- change settings ---
    request = {
        "command": "change_settings",
        "good_coffee": "true"
    }
    json_send(request)
    response = json_recv()
    print(response)


    # --- get coffee aka. flag ---
    request = {
        "command": "get_coffee"
    }
    json_send(request)
    response = json_recv()
    print(response)
    answer = response['res']
    print(answer.split('it: ', 1)[1])

    return


if __name__ == "__main__":
    main()