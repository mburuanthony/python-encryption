requires package --> cryptography==38.0.1

install with --> pip install cryptography

AES IMPLEMENTATION
------------------
AES is a symmetric encryption mechanism hence the sender and receiver both use the same secret key. 

- Start by importing modules

- Setting the backend
    1. A Backend is an interface that can support operations such as 
    Symmetric encryption, Message digests (Hashing), and Hash-based message authentication codes (HMAC).

    backend = default_backend()


- Creating the key and initialization vector
    1. The key, a single key to e used for both encryption & decryption, can be of any length (128bits, 192bits, 256bits). 
        The selected size of the key sets the AES block size.
        - To use 128 bits length pass a value of 16 as a parameter to the key generating method. i.e os.urandom(16)
        - To use 192 bits length pass a value of 24 as a parameter to the key generating method. i.e os.urandom(24)
        - To use 256 bits length pass a value of 32 as a parameter to the key generating method. i.e os.urandom(32)
    2. The initialization vector (iv) is always a randomly generated value that has the size of the AES block (128 bits)
    
    key = os.urandom(32)
    iv = os.urandom(16)


- Creating a cipher object 
    1. The cipher object takes an Algorithm argument. AES for this case.
    2. A mode. CBC for this case. Cipher Block Chaining which is cryptographically strong.
    3. A backend. default_backends for this case.

    cipher = Cipher(algorithm=algorithms.AES(
        key), mode=modes.CBC(iv),  backend=backend)


- Creating encryptor and decryptor objects
    1. The encryptor object is used to encrypt plaintext
    2. The decryptor object is used in decryption

    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

- The rest are functions that use the above created objects (cipher, key, decryptor, encryptor)

- Running the program
    1. The main() function is the entry point for the program
    2. Use a try except block to catch any errors & exceptions
    3. When the program catces a ValueError, it prints an error message then stops excecution.
    4. When the program catces the KeyboardInterrupt exception and stops excecution.
    5. The ValueError exception implies that the provided input exceeds or is less than the number of bits 
        required by the selected AES block size.
    6. The provided string in the printed error message is of sufficient size.

    if __name__ == '__main__':
        try:
            main()
        except ValueError:
            print('The length of the provided data is not a multiple of the block length. Try -: Merry christmas! :-')
            abort()
        except KeyboardInterrupt:
            abort()