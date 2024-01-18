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
PORT = 50406

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


def interval_search(l, r, c0_mod, m0_mod, ctxt):
    interval_len = r - l
    guess = l + int(interval_len / 2)
    
    zeros = (0).to_bytes(16, 'big')
    ctxt_mod = ctxt + guess * zeros
    # ask oracle, answer: 0 = err, 1 = suc
    leak = leak_request(c0_mod, m0_mod, ctxt_mod)
    if 'error' in leak:
        answer = 0
    else:
        answer = 1

    # final case, stopping condition for very last block
    if interval_len == 1:
        return True, r, 0, 0

    # stopping condition for all blocks but last
    if interval_len == 2:
        # query middle element (= guess)
        if answer == 0:
            return True, r, 0, 0
        else:
            return True, guess, 0, 0

    # interval length: 4 or longer
    if answer == 0:
        return False, 0, guess, r
    else:
        return False, 0, l, guess



def main():
    # ------init: get m0, c0 and encrypted message (containing secret)---
    request = {
        "command": "flag"
    }
    json_send(request)
    response = json_recv()
    
    c0 = bytes.fromhex(response["c0"])
    m0 = bytes.fromhex(response["m0"])
    ctxt = bytes.fromhex(response["ctxt"])

    # indeces equal IGE scheme 
    ciphertxt_blocks = blockify(c0 + ctxt)

    # separate content from previous blocks: block c6 is first block containing 'content'
    c_content = ciphertxt_blocks[6:]
    p_content = blockify(b"Thank you for using Montone messaging services. Here is a flag that you will not be able to obta")
    m_header = b"MONTONE-PROTOCOL"
    zeros = (0).to_bytes(16, 'big')
    queries = 0
    flag_start_id = 6


    # TODO: for loop until end of ciphertext_content, start with c_i = ciphertext_content[6]
    #for i in range(6, len(c_content)):
    for i in range(flag_start_id, 12):
        c_i = c_content[i]
        c_i_minus_1 = c_content[i-1]
        c_i_minus_2 = c_content[i-2]
        m_i_minus_1 = p_content[i-1]
        m_i_minus_2 = p_content[i-2]

        # craft ctxt_mod
        c1_mod = c_i_minus_1
        c2_mod = xor(xor(c_i, m_i_minus_1), m_header)
        #ctxt_mod = c1_mod + c2_mod + 128 * zeros

        # craft m0_mod and c0_mod
        m0_mod = m_i_minus_2
        R = xor(m_i_minus_1, c_i_minus_2)
        c0_mod = xor(R, m_header)

        # whether upper bound for num_blocks has been found
        found_bound = False
        found_exact = False
        exp = 0

        # special case of 0 blocks
        ctxt_mod = c1_mod + c2_mod
        leak = leak_request(c0_mod, m0_mod, ctxt_mod)
        queries += 1
        # if appending 0 blocks is the right thing to do
        if 'metadata' in leak:
            found_bound = True
            response = leak['metadata']
            sender, receiver, ts, v_maj, v_min = parse_repr(response)
            m_i = sender + receiver + ts + v_maj + v_min + (0).to_bytes(1, 'big')
            p_content.append(m_i)


        while(found_bound == False):
            num_blocks = 2**exp
            ctxt_mod = c1_mod + c2_mod + num_blocks * zeros
            leak = leak_request(c0_mod, m0_mod, ctxt_mod)
            queries += 1
            # enough blocks appended
            try:
                response = leak['metadata']
                found_bound = True
                sender, receiver, ts, v_maj, v_min = parse_repr(response)
                m_i = sender + receiver + ts + v_maj + v_min
                print('UPPER BOUND num_blocks: ', num_blocks)

                # find the exact number of blocks
                l = num_blocks // 2
                r = num_blocks
                while(found_exact == False):
                    # query interval search
                    found_exact, exact_blocks, l_update, r_update = interval_search(l, r, c0_mod, m0_mod, c1_mod + c2_mod)
                    l = l_update
                    r = r_update 
                    queries += 1

                # now: found exact number
                last_byte = (exact_blocks).to_bytes(1, 'big')
                m_i += last_byte
                print('num_blocks appended: ', exact_blocks)
            
            # did not append enough blocks
            except:
                exp += 1

        # add newly found plaintext to p_content
        p_content.append(m_i)

    # nicely format output
    print('TOTAL QUERIES: ', queries)
    flag = b''
    for id in range(6, len(p_content)):
        flag += p_content[id]
    print(flag)
    print(str(flag[4:], 'utf-8'))

    return



if __name__ == "__main__":
    main()