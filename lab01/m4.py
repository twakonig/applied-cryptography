def xor(A, B):
    return bytes([a ^ b for (a, b) in zip(A, B)])

otp1 = '9b51325d75a7701a3d7060af62086776d66a91f46ec8d426c04483d48e187d9005a4919a6d58a68514a075769c97093e29523ba0'
otp2 = 'b253361a7a81731a3d7468a627416437c22f8ae12bdbc538df0193c581142f864ce793806900a6911daf213190d6106c21537ce8760265dd83e4'
c1 = bytes.fromhex(otp1)
c2 = bytes.fromhex(otp2)

m = ''
m1 = b""
m2 = b"flag{"
b = len(m2)

for i in range(0, len(c1), b):
    key = xor(c2[i:i + b], m2)
    flag = xor(c1[i: i + b], key)
    m += flag.decode(encoding='utf-8)')

print(m)

