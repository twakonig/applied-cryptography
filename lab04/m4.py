#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50404

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


def main():

    # length of message fields (9, 6, 6)
    len_field1 = len("filename=")
    len_field2 = len("&data=")
    len_field3 = len("&flag=")

    block_sz = 16
    b = (0).to_bytes(1, 'big')

    # make test query to see num_blocks of flag (round up because of padding)
    response = encryption_request(b''.decode('utf-8'), b''.hex())
    ctxt = bytes.fromhex(response['ctxt'])
    num_blocks = (len(ctxt) - len_field1 - len_field2 - len_field3) // 16 + 1

    # chose #bytes to fill exactly one block
    file_name = (block_sz - len_field1) * b
    
    # prepare to decypher one block
    decoded_bytes = b''

    # decypher one block (i = #chars after &flag= until end of block)
    for i in range(num_blocks * block_sz):
        # 0s padding after '&data=' keyword
        data_padding = (block_sz - len_field2 + (block_sz - len_field3 - i - 1) + (num_blocks - 1) * block_sz) * b

        # GUESS last byte of block
        for g in range(256):
            guess_byte = (g).to_bytes(1, 'big')
            # prepare 'data' input
            data = data_padding + b'&flag=' + decoded_bytes + guess_byte + b'filename=' + file_name + b'&data=' + data_padding
            response = encryption_request(file_name.decode('utf-8'), data.hex())
            ciphertext = bytes.fromhex(response['ctxt'])
            c8 = ciphertext[7*block_sz : 8*block_sz]
            c16 = ciphertext[15*block_sz : 16*block_sz]
            if c8 == c16:
                print("GUESSED BYTE NR. ", i + 1)
                # print('byte = ', guess_byte)
                decoded_bytes += guess_byte
                # print('decoded bytes: ', decoded_bytes)
                break

        print('...')

    print(decoded_bytes)
    print(decoded_bytes[:-1])
    
    return


if __name__ == "__main__":
    main()