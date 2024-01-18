#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50403

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

def encryption_request(file_name, data):
    request = {
        "command": "encrypt",
        "file_name": file_name,
        "data": data
    }
    json_send(request)
    response = json_recv()
    return response

def solve_request(byte):
    request = {
        "command": "solve",
        "solve": byte
    }
    json_send(request)
    response = json_recv()
    return response


def main():

    block_sz = 16
    padding = 3 * (3).to_bytes(1, 'big')

    # perform 10 guesses before retrieving the flag
    for i in range(10):
        for s in range(256):
            secret_testbyte = (s).to_bytes(1, 'big')
            file_name = b"1234567"
            data = b"123456789&secret_byte=" + secret_testbyte + padding + b"filename=1234567&data=123456789"
            response = encryption_request(file_name.decode('utf-8'), data.hex())
            ctxt = bytes.fromhex(response['ctxt'])
            c2 = ctxt[2*block_sz : 3*block_sz]
            c5 = ctxt[5*block_sz : 6*block_sz]
            if c2 == c5:
                # print("SECRET BYTE FOUND!")
                # print('s = ', secret_testbyte)
                success = solve_request(secret_testbyte.hex())
                print(success)
                break

    request = {
        "command": "flag"
    }
    json_send(request)
    response = json_recv()
    print(response['flag'])

    return
    

if __name__ == "__main__":
    main()