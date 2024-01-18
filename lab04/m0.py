#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50400

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

    # IDEA: brute-forcing, compare against dictionary
    keys = {}
    for id in range(2**16):
        key = (id).to_bytes(2, 'big')
        hash_key = SHA256.new(key).digest()
        keys[id] = hash_key
    print('done generating keys')
    
    m = b'1234567890123456'
    # encryptions of message m under k_l (all keys in dictionary)
    enc_l_m = {}
    for k in range(2**16):
        cipher = AES.new(keys[k], AES.MODE_ECB)
        c = cipher.encrypt(m)
        enc_l_m[c] = k

    print('done encrypting')

    for i in range(64):
        result_found = False
        #--------------request encryption-----------------
        request = {
            "command": "query",
            "m" : m.hex()
        }
        json_send(request)
        response = json_recv()
        c_res = response['res']
        #-------------------------------------------------

        # receive c_res from oracle -> try to decrypt it with all possible keys
        c_query = bytes.fromhex(c_res)
        for k in range(2**16):
            cipher = AES.new(keys[k], AES.MODE_ECB)
            d = cipher.decrypt(c_query)
            # search if this d can be found in encryption dict
            if d in enc_l_m.keys():
                # print('It is in the dictionary! @ k = ', enc_l_m[d])
                request = {
                    "command": "guess",
                    "b" : "0"
                }
                json_send(request)
                response = json_recv()
                print(response)
                result_found = True
                break

        if not result_found:
            # print('not found in dict.')
            request = {
                "command": "guess",
                "b" : "1"
            }
            json_send(request)
            response = json_recv()
            print(response)

    request = {
        "command": "flag"
    }
    json_send(request)
    response = json_recv()
    print(response)
    return
            

if __name__ == "__main__":
    main()