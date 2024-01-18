import json
import telnetlib
import time

from Crypto.PublicKey import RSA
from Crypto.Hash import SHAKE256

TARGET = 256

RSA_KEYLEN = 1024  # 1024-bit modulus
RAND_LEN = 256  # 256-bit of randomness for masking
P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8


# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51004

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ceil(a: int, b: int) -> int:
    # Necessary because of floating point precision loss
    return a // b + (1 if a % b != 0 else 0)


def get_multiplier(m_max: int, m_min: int, N: int, B: int) -> int:
    tmp = ceil(2 * B, m_max - m_min)
    r = tmp * m_min // N
    alpha = ceil(r * N, m_min)
    return alpha, r


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def c_times_s_to_e(c_int, s, e, N):
    s_to_e = pow(s, e, N)
    c_prime = (c_int * s_to_e) % N
    c_prime = c_prime.to_bytes(RSA_KEYLEN // 8, 'big')
    return c_prime


def query_decryption_oracle(c_prime):
    request = {
        "command": "decrypt",
        "ctxt": c_prime.hex()
    }
    json_send(request)
    response = json_recv()
    return response


def oracle(ctxt_int, e, N):
    # leading zeros of R
    leading_zeros = -1
    # base = 2**10

    # get decryption of modified ctxt, c_prime = c * s^e mod N
    for i in range(0, 1016):
        # shift m by 1 bit to the left at decryption oracle
        s = pow(2, i)
        c_prime = c_times_s_to_e(ctxt_int, s, e, N)
        resp = query_decryption_oracle(c_prime)
        try:
            # valid decryption
            msg = resp["res"]
            # base -= 8
            leading_zeros += 1
        except:
            msg = resp["error"]
            if "Eror" in msg:
                # check 2 failed
                leading_zeros += 1
            else:
                # check 1 failed
                break

    m_nbits = 2**10 - 8 - leading_zeros
    # m_nbits = base - leading_zeros
    return m_nbits


def main():

    # get RSA public parameters N and e
    request = {
        "command": "get_params"
    }
    json_send(request)
    response = json_recv()

    # N is 1024 bits, e = 65537
    N = response["N"]
    e = response["e"]

    # get encryption of flag
    request = {
        "command": "flag"
    }
    json_send(request)
    response = json_recv()
    ctxt = bytes.fromhex(response["flag"])
    ctxt_int = int.from_bytes(ctxt, "big")

    # get nuber of bits of m (i = m_nBits)
    i = oracle(ctxt_int, e, N)
    print('i = ', i)

    # define m_min and m_max for start interval, constant variable B
    m_min = 2**(i - 1)
    m_max = (2**i) - 1
    B = 2**(RSA_KEYLEN - 8)     # 2^1016 (max(m_max) = 2^1016 - 1)

    # -----------------------DO STEP2 AND STEP3---------------------------------
    ######################### Find alpha_0#######################
    l = 1023 - i
    n_prev = 0
    alpha_0 = pow(2, l)
    for i in range(2**17):
        alpha_0 += 1
        alpha_0_to_e = pow(alpha_0, e, N)
        c_prime = (ctxt_int * alpha_0_to_e) % N
        resp = query_decryption_oracle(
            int.to_bytes(c_prime, RSA_KEYLEN // 8, 'big'))
        print(resp)
        nBits = oracle(c_prime, e, N) - 2 + 8
        print('nBits = ', nBits, 'i = ', i)
        if nBits < n_prev:
            # this alpha_0 incurrs modular reduction
            break
        else:
            n_prev = nBits

    # know that a_0 * m >= N, and ((alpha_0 -1) *m < N
    m_min = ceil(N, alpha_0)
    m_max = ceil(N, alpha_0 - 1)

    # improve bounds by B query
    c_prime = (ctxt_int * pow(alpha_0 - 1, e, N)) % N
    resp = query_decryption_oracle(
        int.to_bytes(c_prime, RSA_KEYLEN // 8, 'big'))
    print(resp)
    nBits = oracle(c_prime, e, N) - 2 + 8
    if nBits > B:
        m_min = ceil(B, alpha_0 - 1)
    else:
        m_max = ceil(B, alpha_0 - 1)

    alpha, r = get_multiplier(m_max, m_min, N, B)
    print('alpha = ', alpha)
    print('r = ', r)

    # start binary search
    x_min = alpha*m_min
    x_max = alpha*m_max

    # recompute until x_min = m_max -1
    while x_min != m_max - 1:

        # compute val = B + r*N
        val = B + r*N
        if val < x_min:
            print("upper")
            x_max = x_min
            x_min = val
        elif val > x_max:
            print("lower")
            x_min = x_max
            x_max = val
        elif val > x_min and val < x_max:
            # qury to decryption oracle
            # improve bounds by B query
            c_prime = (ctxt_int * pow(val, e, N)) % N
            resp = query_decryption_oracle(
                int.to_bytes(c_prime, RSA_KEYLEN // 8, 'big'))
            print(resp)
            nBits = oracle(c_prime, e, N) - 2
            print(nBits)
            print(m_min.bit_length())
            print(m_max.bit_length())
            break

        # update x_min and x_max

    # find new alpha and r
    m_max = ceil(x_max, alpha)
    m_min = ceil(x_min, alpha)
    alpha, r = get_multiplier(m_max, m_min, N, B)
    print(m_min)
    print(m_max)
    print(m_max - m_min)

    # found integer m_int
    # ---------------------------------------------------------------------------

    # # recover p from m_int and print flag
    # m_bytes = m_int.to_bytes(RSA_KEYLEN // 8, 'big')
    # R = m_bytes[1:1+RAND_LEN//8]
    # p_masked = m_bytes[1+RAND_LEN//8:]
    # hash_R = SHAKE256.new(R).read(P_LEN)
    # p_padded = xor(p_masked, hash_R)
    # for i, b in enumerate(p_padded):
    #     if b == 1 and all(ch == 0 for ch in p_padded[:i]):
    #         p_bytes = p_padded[i+1:]

    # flag = p_bytes.decode('utf-8')
    # print(flag)

    return


if __name__ == "__main__":
    main()
