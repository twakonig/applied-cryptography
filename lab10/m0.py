import math
import json
import telnetlib

from Crypto.PublicKey import DSA
from Crypto.Hash import MD5, HMAC, SHA256

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51000

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


def sign_query(msg):
    request = {
        "command": "sign",
        "message": msg
    }
    json_send(request)
    response = json_recv()
    return response['r'], response['s']


def main():

    # get DSA parameters and public key of server
    request = {
        "command": "get_params"
    }
    json_send(request)
    response = json_recv()
    # print(response)
    g = response['g']
    p = response['p']
    q = response['q']

    # genreate MD5 collision
    m1 = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
    m2 = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"

    # sign queries, r1 and r2 are the same because of collision
    r1, s1 = sign_query(m1)
    r2, s2 = sign_query(m2)

    # find k
    H_m1 = int.from_bytes(SHA256.new(bytes.fromhex(m1)).digest(), "big")
    H_m2 = int.from_bytes(SHA256.new(bytes.fromhex(m2)).digest(), "big")
    k = (pow((s1 - s2), -1, q) * (H_m1 - H_m2)) % q
    print('k:', k)

    # find secret key x
    x = (pow(r1, -1, q) * (k * s1 - H_m1)) % q
    print('x:', x)

    # sign message of choice
    m_star = b"Give me a flag!"
    H_m_star = int.from_bytes(SHA256.new(m_star).digest(), "big")
    r_star = r1
    s_star = (pow(k, -1, q) * (H_m_star + x * r_star)) % q

    # request flag
    request = {
        "command": "flag",
        "r": r_star,
        "s": s_star
    }
    json_send(request)
    response = json_recv()
    print(response)

    return


if __name__ == "__main__":
    main()
