from Crypto.Hash import SHA256

message = b'LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteurs.'
key = b''
for i in range(int(len(message) / 16)):
    id = i * 16
    block = message[id:id+16]
    key = key + block[-1].to_bytes(1, byteorder='big')

print(key)
flag = SHA256.new(data=key).hexdigest()
print(flag)