#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50341

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
    # print(response)
    # print('length challenge: ', len(response['res']))
    return response['res']

def guess_challenge(value):
    request = {
        "command": "guess",
        "guess": value.decode('utf-8')
    }
    json_send(request)
    response = json_recv()
    print(response)




def main():

    # iterate over challenges
    for c in range(100):

        challenge = bytearray.fromhex(query_challenge())
        block_size = 16

        iv = challenge[ : block_size]
        ctxt = challenge[block_size : ]
        zeros = (0).to_bytes(16, 'big')
        pad_0x01 = (1).to_bytes(1, 'big')

        # try all possible values for last byte of second-last block
        for i in range(256):
            delta = (i).to_bytes(16, 'big')
            c_delta = xor(iv, delta)
            res = query('decrypt', 'ciphertext', (c_delta + ctxt).hex())
            len_res = len(res['res'])
            print('i: ',i)

            # this delta produced a correct padding (P_16' = 0x01)
            if len_res != 128:
                print('This is correctly padded!')

                test = xor(c_delta, (0).to_bytes(14, "big")+b'\xab\x00')
                res_2 = query('decrypt', 'ciphertext', (test + ctxt).hex())

                # might accidentally be correct because length-k padding
                if len(res_2['res']) != 128:
                    p_last_byte = xor(pad_0x01, delta[15:16])
                    guess_challenge(p_last_byte)
                    break
                
                
    request = {
    "command": "flag"
    }
    json_send(request)
    response = json_recv()
    print(response)


if __name__ == "__main__":
    main()