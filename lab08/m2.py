from Crypto.Util import number
from Crypto.Random import random
import telnetlib
import json
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import math
import libnum

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50802

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
    mod = []
    rem = []
    # get encrypted flag
    for i in range(3):
        request = {
            "command": "encrypted_flag"
        }
        json_send(request)
        response = json_recv()
        print(response)

        N = int(response["N"])
        c = int(response["ctxt"])
        print(long_to_bytes(int(c ** (1./3.))))
        # print('bit length of N:', N.bit_length())
        # print('bit length of c:', c.bit_length())
        tn.close()
        tn.open(host, PORT)

    # for k in range(1, 4):
    #     # print('k = ', k)
    #     cube_root = int((c*k) ** (1./3.))
    #     # print('bit length of cube root:', cube_root.bit_length())
    #     # print(cube_root)
    #     try:
    #         print(long_to_bytes(cube_root).decode('utf-8'))
    #     except:
    #         # print('not a valid ascii string')
    #         continue

    # # TODO: only get first part of flag. What to use the encrypt function for?
    # # encrypt
    # msg = "abc"
    # int_msg = int.from_bytes(msg.encode(), byteorder="big")
    # request = {
    #     "command": "encrypt",
    #     "plaintext": str(int_msg)
    # }
    # json_send(request)
    # response = json_recv()
    # print(response)

    return


if __name__ == "__main__":
    main()
