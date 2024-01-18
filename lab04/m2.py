#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50402

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

def decrypt_query(c0, m0, ctxt):
    """
        Sends decryption request to server, returns hex encoded response.
        Input: Hex encoded strings of required blocks.
    """
    request = {
        "command": "decrypt",
        "c0": c0,
        "m0": m0,
        "ctxt": ctxt
    }
    json_send(request)
    response = json_recv()
    return response


def process_oracle_resp(response):
    """
        Returns True if correct padding was produced.
        Input: Response of padding oracle ('decrypt' request).
    """
    try:
        # possible error msgs: 'Padding is incorrect.' or 'PKCS#7 padding is incorrect.'
        res_error = response['error']
        if "adding is incorrect." in res_error:
            # print("IT'S THE WRONG PADDING!")
            return False
    except:
        # print("No error message detected -> padding is CORRECT!")
        return True


def main():
    # --- flag request ---
    request = {
        "command": "flag"
    }
    json_send(request)
    response = json_recv()

    c0 = bytes.fromhex(response['c0'])
    m0 = bytes.fromhex(response['m0'])
    ctxt = bytes.fromhex(response['ctxt'])


    block_sz = 16
    m = b''
    m1 = b''

    # iterate over all blocks of ciphertext
    for i in range(0, len(ctxt), block_sz):
        # set new m0 and co to next block
        if i > 0:
            c0 = ctxt[i - block_sz : i]
            m0 = m1

        delta_prev = (0).to_bytes(block_sz, 'big')
        c1 = ctxt[i : i + block_sz]
        m = m + m1
        m1 = b''
        # for byte b of a block (length = 16 bytes)
        for b in range(16):
            # try all possible values
            for d in range(256):
                # xored with c0 yields 0x00 in previous bytes
                prev_pad = (0).to_bytes(block_sz - b, 'big') + b * (b).to_bytes(1, 'big')
                delta_zero = xor(delta_prev, prev_pad)
                curr_pad = (0).to_bytes(block_sz - b, 'big') + b * (b+1).to_bytes(1, 'big')
                # delta: brings overall correct padding for m1
                delta_candidate = (d).to_bytes(block_sz - b, 'big') + b * (0).to_bytes(1, 'big')
                delta = xor(xor(delta_candidate, delta_zero), curr_pad)            
                c0_tmp = xor(c0, delta)

                # send c0_tmp along with c1 (= ctxt) to padding oracle (m0 unchanged)
                response = decrypt_query(c0_tmp.hex(), m0.hex(), c1.hex())
                valid_padding = process_oracle_resp(response)

                # padding invalid
                if not valid_padding:
                    continue
                # padding valid and in case b == 0
                elif valid_padding and b == 0:
                    # check for possible length-k padding
                    c0_tmp2 = xor(c0_tmp, (0).to_bytes(14, "big")+b'\xab\x00')
                    response = decrypt_query(c0_tmp2.hex(), m0.hex(), c1.hex())
                    still_valid_padding = process_oracle_resp(response)

                    # if padding is still valid, we produced what we wanted
                    if not still_valid_padding:
                        continue
                    else:
                        # calculate byte from plaintext
                        padding_byte = (b+1).to_bytes(1, 'big')
                        ptxt_byte = xor(padding_byte, delta[15:16])
                        delta_prev = delta
                        m1 = ptxt_byte + m1
                        print('m1 = ', m1)
                        break
                # padding valid and b > 0
                else:
                    # calculate byte from plaintext
                    byte_id = block_sz - 1 - b
                    padding_byte = (b+1).to_bytes(1, 'big')
                    ptxt_byte = xor(padding_byte, delta[byte_id : byte_id + 1])
                    delta_prev = delta
                    m1 = ptxt_byte + m1
                    print('m1 = ', m1)
                    break

        print('decryption of message so far: m = ', m + m1)

    print(m + m1)
    return
                

if __name__ == "__main__":
    main()