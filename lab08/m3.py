from Crypto.Util import number
from Crypto.Random import random
import telnetlib
import json
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import math

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50803

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
    print(response)

    return


if __name__ == "__main__":
    main()
