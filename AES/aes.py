import os
from os import abort
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# use default backends
backend = default_backend()
# replace -:key = os.urandom(32):- values with 16(for 128 bits), 24(for 192 bits), 32(for 256 bits)
key = os.urandom(32)
# create initialization vector
iv = os.urandom(16)

# creating a cipher object
cipher = Cipher(algorithm=algorithms.AES(
    key), mode=modes.CBC(iv),  backend=backend)


# creating encryptor & decryptor objects
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()


def get_plaintext():
    # function to get plaintext from standard input
    plain_text = str(input('Enter a message to encrypt:\t'))
    return plain_text


def encrypt_plaintext(plaintext):
    # function to encrypt plaintext using encryptor object
    cipher_text = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return cipher_text


def decrypt_cipher(cipher_text):
    # function to decrypt ciphertext using decryptor object
    decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()
    return decrypted_text


def main():
    plaintxt = get_plaintext()
    ciphertxt = encrypt_plaintext(plaintext=plaintxt)
    decrypted_text = decrypt_cipher(cipher_text=ciphertxt)

    print('PLAIN TEXT\t', plaintxt)
    print('CIPHER TEXT\t', ciphertxt)
    print('DECRYPTED TEXT\t', decrypted_text)


if __name__ == '__main__':
    try:
        main()
    except ValueError:
        print('The length of the provided data is not a multiple of the block length. Try -: Merry christmas! :-')
        abort()
    except KeyboardInterrupt:
        abort()
