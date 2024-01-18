#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50342

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
    response = json_recv()
    # print(response)
    # print('length res: ', len(response['res']))
    return response

def query_challenge():
    request = {
        "command": "challenge"
    }
    json_send(request)
    response = json_recv()
    print(response)
    print('length challenge: ', len(response['res']))
    return response['res']

def guess_challenge(value):
    request = {
        "command": "guess",
        "guess": value.hex()
    }
    json_send(request)
    response = json_recv()
    print(response)




def main():

    # # iterate over challenges
    # for c in range(10):

    challenge = (query_challenge()).encode()
    block_size = 16

    iv = challenge[ : block_size]
    ctxt = challenge[block_size : ]
    zeros = (0).to_bytes(16, 'big')

   



        # # try all possible values for last byte of second-last block
        # for i in range(256):
        #     delta = zeros + (i).to_bytes(16, 'big') + zeros
        #     c_delta = iv + xor(ctxt, delta)
        #     res = query('decrypt', 'ciphertext', c_delta.hex())
        #     len_res = len(res['res'])

        #     # this delta produced a correct padding (P_16' = 0x01)
        #     if len_res != 128:
        #         print('This is correctly padded!')
        #         pad_0x01 = (1).to_bytes(1, 'big')

        #         print('challenge ciphertext:')
        #         for i in range(0, len(challenge), 16):
        #             print(challenge[i : i+block_size])

        #         print('modified ciphertext:')
        #         for i in range(0, len(challenge), 16):
        #             print(c_delta[i : i+block_size])

        #         c_tilde = c_delta[47:48]
        #         c_ctxt = challenge[47:48]

        #         print(c_ctxt)
        #         print(c_tilde)
        #         print(pad_0x01)
                
        #         p_last_byte = xor(xor(pad_0x01, c_tilde), c_ctxt)
        #         guess_challenge(p_last_byte)
        #         break



   

    




if __name__ == "__main__":
    main()