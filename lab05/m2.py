from Crypto.Hash import MD5


def main():
    # given pw hash
    pw_hash = '9fb7009f8a9b4bc598b4c92c91f43a2c'
    ctr = 1

    # check rockyou database
    with open('rockyou.txt', 'rb') as f:
        for line in f:
            print('chacking pw nr.: ', ctr)
            s_line = line.rstrip()
            md5 = MD5.new()
            md5.update(s_line)
            test_hash = md5.hexdigest()
            ctr += 1
            if test_hash == pw_hash:
                print('THE PASSWORD IS: ', s_line)
                return
   

if __name__ == "__main__":
    main()