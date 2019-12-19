# Read plaintext from the file
file = open('plaintext.txt', 'r')
plaintext = file.read()
cipher = ""
plain = ""
key = 87

# convert letters to ascii, add our key and bit shift by 2
for i in range(len(plaintext)):
    a = ord(plaintext[i])
    a += key
    b = a << 2
    print('a=',a,'b=',b)
    cipher += str(b)

# get the cipher text, bit shift back by 2, subtract our key and convert ascii back to characters
for i in range(0, len(cipher), 3):
    c = cipher[i:i+3]
    b = int(c) >> 2
    b -= key
    plain += chr(b)

print("Original message: ", plaintext)
print("Encrypted text: ", cipher)
print("Decrypted text: ", plain)
