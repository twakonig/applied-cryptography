input = '596f752063616e206465636f646521'
flag = bytes.fromhex(input).decode(encoding='utf-8')
print(flag)