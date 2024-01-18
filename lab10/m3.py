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
PORT = 51003

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


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

    for j in range(TARGET):
        # get encryption of random message p
        request = {
            "command": "get_challenge"
        }
        json_send(request)
        response = json_recv()
        # 128 byte ciphertext (bytes(m^e mod N))
        ctxt = bytes.fromhex(response["challenge"])
        ctxt_int = int.from_bytes(ctxt, "big")

        # leading zeros of R
        leading_zeros = -1

        # get decryption of modified ctxt, c_prime = c * s^e mod N
        # need only 256 to cover whole block of R. to ecover all of m in case of all 0 string, range is set to 127*8
        for i in range(0, 1016):
            # shift m by 1 bit to the left at decryption oracle
            s = pow(2, i)
            c_prime = c_times_s_to_e(ctxt_int, s, e, N)
            # print('s = ', s)
            # print("num_bits of c_prime: ", int.from_bytes(c_prime, 'big').bit_length())
            resp = query_decryption_oracle(c_prime)
            try:
                msg = resp["res"]
                # print(resp)
                # print("------> VALID DECRYPTION")
                leading_zeros += 1
            except:
                msg = resp["error"]
                if "Eror" in msg:
                    # print(resp)
                    # print(" --> CHECK 2 FAILED = fine, more leading zeros")
                    leading_zeros += 1
                else:
                    # print(resp)
                    # print(" --> CHECK 1 FAILED = 1 bit in first byte")
                    break

        m_nbits = 2**10 - 8 - leading_zeros
        print('BITS GUESSED = ', m_nbits)

        # send solve command
        request = {
            "command": "solve",
            "i": m_nbits
        }
        json_send(request)
        response = json_recv()
        # print(response)
        # print('------------------------------------------------')

    # request and print flag
    request = {
        "command": "flag"
    }
    json_send(request)
    response = json_recv()
    print(response)

    return


if __name__ == "__main__":
    main()
