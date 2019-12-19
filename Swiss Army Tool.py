# Reference: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# Reference: https://cryptography.io/en/latest/hazmat/primitives/padding/
# Reference: https://cryptography.io/en/latest/fernet/
# Reference: https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
# Reference: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
# Reference: https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/

choice = 0
while choice != '4':
    print("""
   _____         _              ___                            ______            __
  / ___/      __(_)_________   /   |  _________ ___  __  __   /_  __/___  ____  / /
  \__ \ | /| / / / ___/ ___/  / /| | / ___/ __ `__ \/ / / /    / / / __ \/ __ \/ / 
 ___/ / |/ |/ / (__  |__  )  / ___ |/ /  / / / / / / /_/ /    / / / /_/ / /_/ / /  
/____/|__/|__/_/____/____/  /_/  |_/_/  /_/ /_/ /_/\__, /    /_/  \____/\____/_/   
                                                  /____/                           
                        """)
    choice = input("[0] Fernet Encrpytion \n"
                   "[1] AES Encrpytion \n"
                   "[2] RSA Encrpytion \n"
                   "[3] Quit \n"
                   "Option: ")
    if choice == '0':
        from cryptography.fernet import Fernet
        # generates a Fernet key
        key = Fernet.generate_key()
        fernet = Fernet(key)

        message = input("Enter a message: ")
        message_to_bytes = bytes(message, 'utf-8')

        # We encrypt our message, which needs to be in bytes
        encrypt = fernet.encrypt(message_to_bytes)

        # Decrypts our encrypted text
        decrypt = fernet.decrypt(encrypt)

        # Prints our encrypted and decrypted text
        print('Fernet Encryption: ', encrypt)
        print('Fernet Decryption:', decrypt.decode('utf-8'), '\n')
        print('Fernet Encrpytion Educational Brief (Symmetric Encryption):\nA Fernet key was generated using a cryptography library.'
              ' This key is composed of 128 bit AES key(Encryption) and 128 bit SHA256 HMAC \nsigning key(Authentication).'
              'This Fernet key is then used to encrypt and decrypt fernet tokens. The original plaintext message you entered \nis then '
              'converted to bytes before it serves as a token to be encrypted. The decryption function then takes the ciphertext as a token'
              ' to be \nconverted back to the original plaintext. Both texts are then displayed. N.B It is important that the key is kept secure as the'
              'as the message \ncan not be altered or read without the key hence symmetric encryption.\n   ')

    if choice == '1':
        import os
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        backend = default_backend()
        # User enters their message
        plain_text = input("Enter your plaintext:")
        plaintext_to_bytes = bytes(plain_text, 'utf-8')

        # Padding adds random text to fit the block size
        padder = padding.PKCS7(128).padder()
        padder_data = padder.update(plaintext_to_bytes)
        padder_data += padder.finalize()

        # Key and IV will generate 32 and 16 random characters
        mykey = os.urandom(32)
        initial_value = os.urandom(16)

        # Generates the AES encryption method
        cipher = Cipher(algorithms.AES(mykey), modes.CBC(initial_value), backend=backend)

        # Used to encrypt our plaintext
        encrypt = cipher.encryptor()
        encrypt_text = encrypt.update(padder_data) + encrypt.finalize()

        # Used to decrypt our encrypted text
        decrypt = cipher.decryptor()
        decrypt_text = decrypt.update(encrypt_text) + decrypt.finalize()

        # Takes out the random text from our cipher
        unpadder = padding.PKCS7(128).unpadder()
        unpadder_data = unpadder.update(decrypt_text)
        original_message = unpadder_data + unpadder.finalize()

        # Prints our encrypted and decrypted message
        print("AES Encrpytion: ", encrypt_text)
        print("AES Decryption: ", original_message.decode('utf-8'), '\n')
        print('Advanced Encryption Standard Educational Brief (AES):\nFirst off, it is important to understand AES is a '
              'symmetric block cipher. The original plaintext message is then converted to bytes \nbefore it is passed to '
              'the Padder function PKCS7. Padding genrally means adding random data to parts of a message prior to encryption \nto make message unpredictable.'
              'PKCS7 takes the plaintext and adds bytes of random data depending on the size of the block boundary that \nneeds to be satisfied before passing to the'
              'encryption algorithm. A key of length 32 bytes is randomly produced, the algorithm is then \nreferred to as AES-256. The padded message is then passed'
              'to the AES encryption algorithm along with the Cipher Block Chaining \nMode of Operation which takes a random IV. This ensures '
              'every time a message is encrypted that the ciphertext is different. \nThe ciphertext is then displayed. The Decryption algorithm,'
              'takes the ciphertext and then runs the encryption algorithm in \nreverse order to produce plaintext. Both messages are then displayed.')

    if choice == '2':
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        # generates private and public key and pem file
        privateK = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        publicK = privateK.public_key()
        pem = privateK.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # writes the data of the private key into the private.pem file
        with open("private.pem", "wb") as key_file:
            key_file.write(pem)

        # creates pem file for public key
        pem = publicK.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # writes public key data into "public.pem" file
        with open("public.pem", "wb") as key_file:
            key_file.write(pem)

        # reads data from key files
        with open("private.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        with open("public.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

        plain = input("Enter message: ")
        # encrypts users desired message
        encrypted = public_key.encrypt(
            bytes(plain, 'utf-8'),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        print("Secret message: ", encrypted)

        # decrypts users message
        unencrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        print("Original message: ", unencrypted.decode('utf-8'), '\n')
        print("Rivest-Shamir-Adleman Brief (RSA): \nThis algorithm is a Public Key Encryption Algorithm, it uses"
              "a Public Key = to {e,n}. The Public Key is generated using a built in function \nand this key was written to a file where it "
              "can be kept secured. The key_size was set to 2048 which improves security and reduces \nthe Brute Force Attack. The algorithm "
              "then takes the original plaintexts bytes and encrypts it with the public key as well as padding \nwhich adds random data to the "
              "encrypted message to fit the block size and to generally improve security against probable attacks. \nThe decryption algorithm "
              "then uses the private key generated to convert the ciphertext back to the original message and then displays both texts.")
    if choice == '3':
        break

print("Thank you for using our Swiss Army Tools")
