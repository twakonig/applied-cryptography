import json
import telnetlib


# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51001

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


def encrypt_query(message, nonce):
    request = {
        "command": "encrypt",
        "message": message,
        "nonce": nonce
    }
    json_send(request)
    response = json_recv()
    try:
        print(response)
        c = bytes.fromhex(response['ciphertext'])
        t = bytes.fromhex(response['tag'])
        return c, t
    # error occurred in encryption
    except:
        print(response)
        return 0, 0


def decrypt_query(ciphertext, tag, nonce):
    request = {
        "command": "decrypt",
        "ciphertext": ciphertext,
        "tag": tag,
        "nonce": nonce
    }
    json_send(request)
    response = json_recv()
    print(response)


def main():

    # calculations mod p
    p = 2**127 - 1

    # set nonce once (adversary not nonce-respecting)
    nonce = b'00000000'

    # ---------------FIND CIPHERTEXT------------------------
    # first encryption query
    msg_1 = "Give me a flag."
    ctxt_1, tag_1 = encrypt_query(msg_1, nonce.hex())

    # second encryption query
    msg_2 = "This is a flag!"
    ctxt_2, tag_2 = encrypt_query(msg_2, nonce.hex())

    # ciphertext of "Give me a flag!"
    ctxt_star = ctxt_1[:8] + ctxt_2[8:]

    # ---------------FIND TAG------------------------

    # first encryption query
    msg_i = "000000000000000"
    ctxt_1, tag_1 = encrypt_query(msg_i, nonce.hex())

    # second encryption query
    msg_ii = "000000000000001"
    ctxt_2, tag_2 = encrypt_query(msg_ii, nonce.hex())

    # convert values to integers
    c1_int = int.from_bytes(ctxt_1, 'big') % p
    c2_int = int.from_bytes(ctxt_2, 'big') % p
    t1_int = int.from_bytes(tag_1, 'big') % p
    t2_int = int.from_bytes(tag_2, 'big') % p

    # subtract tags
    diff_t = (t2_int - t1_int) % p
    delta_c = (c2_int - c1_int) % p

    # compute K^2 and then K (make use of: p mod 4 == 3)
    K_sq = (diff_t * pow(delta_c, -1, p)) % p
    exponent = ((p + 1) // 4) % p

    # two square roots of K_sq mod p
    K_pos = pow(K_sq, exponent, p)
    K_neg = -K_pos % p

    # compute mask_int from some valid c, t pair (msg_i)
    h_1_pos = (K_pos**3 + c1_int * K_pos**2 + len(msg_i) * K_pos) % p
    h_1_neg = (K_neg**3 + c1_int * K_neg**2 + len(msg_i) * K_neg) % p

    mask_pos = (t1_int - h_1_pos) % p
    mask_neg = (t1_int - h_1_neg) % p

    # compute hash for ctxt_star
    c_star = int.from_bytes(ctxt_star, 'big') % p
    h_star_pos = (K_pos**3 + c_star * K_pos**2 + 15 * K_pos) % p
    h_star_neg = (K_neg**3 + c_star * K_neg**2 + 15 * K_neg) % p

    # compute two possible tags for ctxt_star
    tag_star_pos = (h_star_pos + mask_pos) % p
    tag_star_neg = (h_star_neg + mask_neg) % p

    tag_star_pos = tag_star_pos.to_bytes(16, 'big')
    tag_star_neg = tag_star_neg.to_bytes(16, 'big')

    # decrypt ctxt_star with the tag that works (both shold work actually)
    try:
        request = {
            "command": "decrypt",
            "ciphertext": ctxt_star.hex(),
            "tag": tag_star_pos.hex(),
            "nonce": nonce.hex()
        }
        json_send(request)
        response = json_recv()
        print(response)
        flag = response['res']
        print(flag)
    except:
        request = {
            "command": "decrypt",
            "ciphertext": ctxt_star.hex(),
            "tag": tag_star_neg.hex(),
            "nonce": nonce.hex()
        }
        json_send(request)
        response = json_recv()
        print(response)
        flag = response['res']
        print(flag)

    return


if __name__ == "__main__":
    main()
