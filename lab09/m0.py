
import telnetlib
import json

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import AES

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50900

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
    # initialize alice and receive pk_A
    # sk = x, pk = g^x mod p
    request = {
        "command": "alice_initialisation"
    }
    json_send(request)
    response = json_recv()
    print(response)

    msg_A = response['resp']
    pk_A = response['alice_key']
    print("msg_A: ", msg_A)
    print("pk_A: ", pk_A)

    return


if __name__ == "__main__":
    main()
