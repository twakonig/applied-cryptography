from Crypto.Hash import SHA256

code = SHA256.new(data=b'hi').hexdigest()
print(code)