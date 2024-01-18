import json
import telnetlib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import isPrime
from Crypto.Util import number
from Crypto.Random import random

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51002

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

    # choose random q (10 bit)
    q = number.getPrime(10)
    q_is_prime = isPrime(q)

    # check again if q is prime
    while q_is_prime == False:
        print('q not yet prime.')
        q = number.getPrime(10)
        q_is_prime = isPrime(q)

    print('q = ', q)

    # compute suitable p
    k = 2**1015
    p = k * q + 1
    p_is_prime = isPrime(p)

    # check if p is prime
    it = 0
    while p_is_prime == False:
        # print('p not yet prime')
        k += 1
        p = k * q + 1
        p_is_prime = isPrime(p)
        it += 1
    print('p = ', p)
    print('bit length of p: ', p.bit_length())

    # p = k * q + 1
    print('k = ', k)
    print('Found prime p after ', it, ' iterations.')

    # find generator g of subgroup of order q (g is generator of G_q qith q elements)
    g = 0
    while ((g <= 1) or (g == p-1)):
        # TODO: is this the right range?
        h = random.randint(2, 2*p)
        g = pow(h, k, p)
    print('g = ', g)
    print('g^q mod p = ', pow(g, q, p))

    # -------------------------SETUP DONE----------------------------------

    # set DHIES parameters p and g
    request = {
        "command": "set_params",
        "p": p,
        "g": g
    }
    json_send(request)
    response = json_recv()
    # print(response)

    # receive pk_Bob
    pk_Bob = response['bob_pubkey'].to_bytes(512, "big")

    # continue by getting encryption of flag now.
    request = {
        "command": "encrypt"
    }
    json_send(request)
    response = json_recv()
    # print(response)

    # store values from EtM scheme
    pk_Server = response['pk'].to_bytes(512, "big")
    ctxt = bytes.fromhex(response['ciphertext'])
    tag = bytes.fromhex(response['tag'])
    N = bytes.fromhex(response['nonce'])

    # try to decrypt for all different values of K
    for j in range(q):
        shared_guess = pow(g, j, p).to_bytes(512, "big")
        K_guess = HKDF(shared_guess + pk_Server + pk_Bob, 32, salt=b"",
                       num_keys=1, context=b"dhies-enc", hashmod=SHA256)
        cipher = AES.new(K_guess, AES.MODE_GCM, N)
        try:
            ptxt = cipher.decrypt_and_verify(ctxt, tag)
            print('plaintext: ', ptxt)
        except:
            continue

    return


if __name__ == "__main__":
    main()
