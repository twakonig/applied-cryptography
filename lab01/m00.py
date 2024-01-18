import hashlib 

code = hashlib.sha224(b"you made it").hexdigest()
print(code)