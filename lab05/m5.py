#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Hash import SHA256, HMAC, MD5
import string
import time
import random

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True
# Remember to change the port if you are re-using this client for other challenges
PORT = 50505

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

    # ask for token
    request = {
        "command": "token"
    }
    json_send(request)
    response = json_recv()

    nonce = bytes.fromhex(response['nonce'])
    token = bytes.fromhex(response['token_enc'])

    # #-------------------------testing-------------------------------
    # m1 = b"Pepper and lemon spaghetti with basil and pine nuts"
    # recipe = b"Heat the oil in a large non-stick frying pan. Add the pepper and cook for 5 mins. Meanwhile, cook the pasta for 10-12 mins until tender. Add the courgette and garlic to the pepper and cook, stirring very frequently, for 10-15 mins until the courgette is really soft. Stir in the lemon zest and juice, basil and spaghetti (reserve some pasta water) and toss together, adding a little of the pasta water until nicely coated. Add the pine nuts, then spoon into bowls and serve topped with the parmesan, if using. Taken from [www.bbcgoodfood.com/recipes/pepper-lemon-spaghetti-basil-pine-nuts]"
    # token = b"username:admin&m1:" + m1 + b"&fav_food_recipe:" + recipe

    # print(len(token))
    # hash = MD5.new(token).digest()
    # print(len(hash))

    # hash_long = MD5.new(token + b'oaidjosdijoierupcmoureupeimoeiruvmpwoerucireou').digest()
    # hash_short = MD5.new(b'1').digest()

    # # all map to the same length: 16 bytes
    # print(len(hash_long))
    # print(len(hash_short))

    # #---------------------------------------------------------------

    # craft m2
    m1 = b"Pepper and lemon spaghetti with basil and pine nuts"
    hash_m1 = MD5.new(m1).digest()
    collision_str = b''

    k_len = len(m1)

    # yields 50% chance of collision
    for i in range(2**64):
        print('try nr.: ', i)
        m2 = (''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=k_len))).encode()
        hash_m2 = MD5.new(m2).digest()
        if hash_m2 == hash_m1:
            print('FOUND COLLISION!')
            print('collision = ', m2)
            collision_str = m2
            break

    # ask to login
    request = {
        "command": "login",
        "token_enc": token.hex(),
        "nonce": nonce.hex(),
        "m2": collision_str.hex()
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

 
    return
            

if __name__ == "__main__":
    main()