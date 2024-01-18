#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import re
from datetime import datetime, timezone
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50405

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

def blockify(s):
    return [s[i : i + 16] for i in range(0, len(s), 16)]

def parse_repr(metadata):
    """Parses a string representation of a Message, returning the metadata fields"""

    majv, minv, src, rcv, ts = re.match(
        r"Montone Protocol \(v(\d+)\.(\d+)\) message from (\d+) to (\d+), sent on (.+)\.",
        metadata,
    ).groups()

    majv = int(majv).to_bytes(2, "little")
    minv = int(minv).to_bytes(1, "little")
    src = int(src).to_bytes(4, "little")
    rcv = int(rcv).to_bytes(4, "little")
    ts = int(datetime.fromisoformat(ts).timestamp()).to_bytes(4, "little")
    return src, rcv, ts, majv, minv


def leak_request(c0, m0, ctxt):
    request = {
        "command": "metadata_leak",
        "c0": c0.hex(),
        "m0": m0.hex(),
        "ctxt": ctxt.hex()

    }
    json_send(request)
    response = json_recv()
    return response


def main():
    # ------init: get m0, c0 and encrypted message (containing secret)---
    request = {
        "command": "init"
    }
    json_send(request)
    response = json_recv()
    
    c0 = bytes.fromhex(response["c0"])
    m0 = bytes.fromhex(response["m0"])
    ctxt = bytes.fromhex(response["ctxt"])

    blocks = blockify(ctxt)
    c1 = blocks[0]
    c2 = blocks[1]
    c3 = blocks[2]

    # request decryption for original message
    leak = leak_request(c0, m0, ctxt)
    msg = leak['metadata']
    sender, receiver, ts, v_maj, v_min = parse_repr(msg)
    guess = (2).to_bytes(1, 'big')

    m2 = sender + receiver + ts + v_maj + v_min + guess

    # craft c0_mod and m0_mod s.t. m1 still yields 'MONTONE-PROTOCOL'
    m1 = b"MONTONE-PROTOCOL"
    m0_mod = m1
    R2 = xor(m2, c1)
    c0_mod = xor(m1, R2)
    c1_mod = c2
    c2_mod = xor(xor(c3, m2), m1)
    zeros = (0).to_bytes(16, 'big')


    blocks_appended = 0
    for r in range(1, 129):
        # double number of blocks appended each time
        print('request nr.: ', r+2)
        blocks_appended = 2**r
        print('nr. of blocks appended: ', blocks_appended)
        ctxt_mod = c1_mod + c2_mod + blocks_appended * zeros
        leak = leak_request(c0_mod, m0_mod, ctxt_mod)
        try:
            secret_msg = leak['metadata']
            print('I FOUND THE SECRET!')
            sender, receiver, ts, v_maj, v_min = parse_repr(secret_msg)
            tmp_secret = sender + receiver + ts + v_maj + v_min
            print(tmp_secret)
            start = blocks_appended // 2 + 1
            num_tries = 129 - r + 2
            # nr. of tries you still have left
            for i in range(num_tries):
                ctxt_mod = c1_mod + c2_mod + (start + i) * zeros
                print('request nr.: ', r+2+i+1)
                print('nr. of blocks appended: ', start + i)
                leak = leak_request(c0_mod, m0_mod, ctxt_mod)
                try:
                    secret_msg = leak['metadata']
                    print('I FOUND THE MISSING BYTE!')
                    secret_byte = start + i
                    print(secret_byte)
                    secret_byte = (secret_byte).to_bytes(1, 'big')
                    secret = tmp_secret + secret_byte
                    break
                except:
                    continue
            break
        except:
            continue

    # request flag
    request = {
        "command": "flag",
        "solve": secret.decode('utf-8')

    }
    json_send(request)
    response = json_recv()
    print(response)

    return
    

if __name__ == "__main__":
    main()