import itertools
import string
from Crypto.Hash import HMAC, SHA1
import time

def main():

    start = time.time()

    # given parameters
    SALT = 'b49d3002f2a089b371c3'
    salt = bytes.fromhex(SALT)
    HASH = 'd262db83f67a37ff672cf5e1d0dfabc696e805bc'

    alphabet = list(string.ascii_lowercase)

    # HMAC: key = pw_candidate, salt = message
    pw_candidates = itertools.product(alphabet, repeat=6)
    for pw in pw_candidates:
        pw_str = ''.join(pw)
        print(pw_str[0:2])
        h = HMAC.new(pw_str.encode(), digestmod=SHA1)
        h.update(salt)
        if h.hexdigest() == HASH:
            print('THE PASSWORD IS: ', pw_str)
            print('Total time: ', time.time() - start)
            return


if __name__ == "__main__":
    main()