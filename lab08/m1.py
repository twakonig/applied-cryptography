from Crypto.Util import number
from Crypto.Random import random
import telnetlib
import json
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50801

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)


def readline():
    return tn.read_until(b"\n")


def json_recv():
    line = readline()
    return json.loads(line.decode())


def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def main():
    # get encrypted flag
    request = {
        "command": "encrypted_flag"
    }
    json_send(request)
    response = json_recv()
    # print(response)

    # from hex to int
    flag_enc = response["encypted_flag"]
    N_int = int(response["N"], 16)
    e_int = int(response["e"], 16)
    print('N: ', N_int)
    print('e: ', e_int)

    c_int = int(flag_enc, 16)

    r = 4
    r_to_e = pow(r, e_int, N_int)
    print('r_to_e: ', r_to_e)

    # send c * r^e mod N, to then divide response by r
    c_prime = (c_int * r_to_e) % N_int
    msg = hex(c_prime)[2:]

    # make decryption query
    request = {
        "command": "decrypt",
        "ciphertext": msg
    }
    json_send(request)
    response = json_recv()
    print(response)

    flag_prime = int(response["res"], 16)
    print(long_to_bytes(flag_prime // r))

    return


if __name__ == "__main__":
    main()
