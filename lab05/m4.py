#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Hash import SHA256, HMAC
import string
import time
import itertools

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50504

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

    start = time.time()

    # ask for salt
    request = {
        "command": "salt"
    }
    json_send(request)
    response = json_recv()
    salt = bytes.fromhex(response['salt'])

    # dictionary with hash:pw pairs
    hash_dict = {}

    # use salt to create hashes for all possible pws of len 5 (dict= hash : pw)
    alphabet = list(string.ascii_lowercase)
    pw_candidates = itertools.product(alphabet, repeat=5)
    for pw in pw_candidates:
        pw_str = ''.join(pw)
        print(pw_str[0:2])
        h = HMAC.new(salt, msg=pw_str.encode(), digestmod=SHA256).hexdigest()
        hash_dict[h] = pw_str

    print('CREATED DICTIONARY OF ALL POSSIBLE HASHES.')

    for i in range(5):
        # ask for password
        request = {
            "command": "password"
        }
        json_send(request)
        response = json_recv()
        pw_hash = response['pw_hash']

        guess = hash_dict[pw_hash]

        # make a guess
        request = {
            "command": "guess",
            "password": guess

        }
        json_send(request)
        response = json_recv()
        print(response)


    # ask for flag
    request = {
        "command": "flag"
    }
    json_send(request)
    response = json_recv()
    print(response)
    print('Total time: ', time.time() - start)

    return
            

if __name__ == "__main__":
    main()