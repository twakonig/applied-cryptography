from Crypto.Util import number
from Crypto.Random import random
import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50800

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

def rsa_key_gen(nbits=2048) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Generates textbook rsa keys
       p: first prime
       q: second prime
       N: p*q
       e: public part
       d: secret key
    Args:
        nbits (int, optional): RSA security parameter

    Returns:
        (N, e), (N, d), (p, q)
        where
        pk = (N, e)
        sk = (N, d)
        primes = (p, q)
    """
    e = 65537
    p = number.getPrime(nbits // 2)
    q = number.getPrime(nbits // 2)
    N = p * q
    binary_N = format(N, 'b')
    # p, q must not be equal, N must have right number of bits
    while (p == q or len(binary_N) != nbits):
        q = number.getPrime(nbits // 2)
        N = p * q
        binary_N = format(N, 'b')

    phi_N = (p - 1) * (q - 1)
    d = number.inverse(e, phi_N)

    pk = (N, e)
    sk = (N, d)
    primes = (p, q)

    return pk, sk, primes


def rsa_enc(pk: tuple[int, int], m: int) -> int:
    """Textbook RSA encryption

    Args:
        pk (int, int): RSA public key tuple
        m (int): the message to encrypt

    Returns:
        int: textbook rsa encryption of m
    """
    c = pow(m, pk[1], pk[0])
    return c


def rsa_dec(sk: tuple[int, int], c: int) -> int:
    """Textbook RSA decryption

    Args:
        sk (int,int): RSA secret key tuple, (N, d)
        c (int): RSA ciphertext

    Returns:
        int: Textbook RSA decryption of c
    """
    # pt = c^d mod N
    pt = pow(c, sk[1], sk[0])
    return pt


def main():
    # compute parameters
    pk, sk, primes = rsa_key_gen()

    # set parameters
    request = {
        "command": "set_parameters",
        "N": pk[0],
        "e": pk[1],
        "d": sk[1],
        "p": primes[0],
        "q": primes[1]
    }
    json_send(request)
    response = json_recv()
    print(response)

    # get encrypted flag
    request = {
        "command": "encrypted_flag"
    }
    json_send(request)
    response = json_recv()
    print(response)

    flag_enc = int(response['res'].split('encrypted: ',1)[1])

    # decrypt flag
    flag_dec = rsa_dec(sk, flag_enc)
    print('This is the FLAG: ')
    print(flag_dec.to_bytes(256, 'big').decode('utf-8'))

    return


if __name__ == "__main__":
    main()