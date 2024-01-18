string_list = ['a', 'a 23 bytes long string', '64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes']

for string in string_list:
   encoding = (8 * len(string)).to_bytes(8, 'big')
   print(encoding.hex(), end=', ')
  
print()