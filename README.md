## RSA & AES encryption algorithms

```bash
#install requirements
# requires --> cryptography==38.0.1

pip install cryptography
```

## AES
AES (Advanced Encryption Standard) is a symmetric encryption mechanism hence the sender and receiver both use the same secret key. 

- Start by importing modules

- Setting the backend
    1. A Backend is an interface that can support operations such as 
    Symmetric encryption, Message digests (Hashing), and Hash-based message authentication codes (HMAC).

    ```python
    backend = default_backend()
    ```

- Creating the key and initialization vector
    1. The key, a single key to e used for both encryption & decryption, can be of any length (128bits, 192bits, 256bits). 
        The selected size of the key sets the AES block size.
        - To use 128 bits length pass a value of 16 as a parameter to the key generating method. i.e os.urandom(16)
        - To use 192 bits length pass a value of 24 as a parameter to the key generating method. i.e os.urandom(24)
        - To use 256 bits length pass a value of 32 as a parameter to the key generating method. i.e os.urandom(32)
    2. The initialization vector (iv) is always a randomly generated value that has the size of the AES block (128 bits)
    
    ```python
    key = os.urandom(32)
    iv = os.urandom(16)
    ```

- Creating a cipher object 
    1. The cipher object takes an Algorithm argument. AES for this case.
    2. A mode. CBC for this case. Cipher Block Chaining which is cryptographically strong.
    3. A backend. default_backends for this case.

    ```python
    cipher = Cipher(algorithm=algorithms.AES(
        key), mode=modes.CBC(iv),  backend=backend)
    ```

- Creating encryptor and decryptor objects
    1. The encryptor object is used to encrypt plaintext
    2. The decryptor object is used in decryption

    ```python
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    ```

- The rest are functions that use the above created objects (cipher, key, decryptor, encryptor)

- Running the program
    1. The main() function is the entry point for the program
    2. Use a try except block to catch any errors & exceptions
    3. When the program catces a ValueError, it prints an error message then stops excecution.
    4. When the program catces the KeyboardInterrupt exception and stops excecution.
    5. The ValueError exception implies that the provided input exceeds or is less than the number of bits 
        required by the selected AES block size.
    6. The provided string in the printed error message is of sufficient size.

    ```python
    if __name__ == '__main__':
        try:
            main()
        except ValueError:
            print('The length of the provided data is not a multiple of the block length. Try -: Merry christmas! :-')
            abort()
        except KeyboardInterrupt:
            abort()
    ```

## RSA

RSA (Rivest–Shamir–Adleman) is an asymmetric encryption mechanism. It uses two different but linked keys, a publik key and a private key, and both keys can encrypt a message.

- Start by importing modules

- Generating keys
    1. Use the inbuilt cryptography method rsa.generate_private_key()
    2. The private key is then used to setup the public key

    ```python
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    ```

-  Saving generated keys to a file
    1. To avoid constatntly creating new keys, we generate the keys once
        then save them to a file.
    2. The function write_keys_to_file() below saves the keys to a file

    ```python
    def write_keys_to_file():
        ...
    ```
    
- Encrypting plaintext
    1. To encrypt plaintext provided by a user, we use the public key.
    2. The public key exposes the encrypt() method.
    3. Padding refers to the nummber of bytes/bits to add to the plaintext (string)
    4. The output of this function is base64 encoded.

    ```python
    encrypted = base64.b64encode(use_pub_key().encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))
    ```

- Decrypting cipher text
    1. Decrypting requires we use the private key.
    2. The private key is aware of the public key, since it was used to generate it.
    3. The private key exposes a decrypt method.
    4. The decrypt method requires these parameters :
                                                    i) base64 encoded cipher text
                                                    ii) padding (bits to be added/removed to/from the cipher text)

    ```python
    decrypted = use_private_key().decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    ```

- Running the program
    1. The main() function is the entry point for the program
    2. Use a try except block to catch any errors & exceptions
    3. When the program catces the KeyboardInterrupt exception and stops excecution.
    4. The KeyboardInterrupt exception implies that the user presses Ctr + c or break
        before the program completes excecution.

    ```python
    if __name__ == '__main__':
        try:
            main()
        except KeyboardInterrupt:
            abort()
    ```