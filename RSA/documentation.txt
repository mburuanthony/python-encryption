requires package --> cryptography==38.0.1

install with --> pip install cryptography

RSA IMPLEMENTATION
------------------
RSA is an asymmetric encryption mechanism. It uses two different but linked keys, a publik key and a private key, and both keys can encrypt a message.

- Start by importing modules

- Generating keys
    1. Use the inbuilt cryptography method rsa.generate_private_key()
    2. The private key is then used to setup the public key

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()


-  Saving generated keys to a file
    1. To avoid constatntly creating new keys, we generate the keys once
        then save them to a file.
    2. The function write_keys_to_file() below saves the keys to a file

    def write_keys_to_file():
        ...

    
- Encrypting plaintext
    1. To encrypt plaintext provided by a user, we use the public key.
    2. The public key exposes the encrypt() method.
    3. Padding refers to the nummber of bytes/bits to add to the plaintext (string)
    4. The output of this function is base64 encoded.

    encrypted = base64.b64encode(use_pub_key().encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))


- Decrypting cipher text
    1. Decrypting requires we use the private key.
    2. The private key is aware of the public key, since it was used to generate it.
    3. The private key exposes a decrypt method.
    4. The decrypt method requires these parameters :
                                                    i) base64 encoded cipher text
                                                    ii) padding (bits to be added/removed to/from the cipher text)

    decrypted = use_private_key().decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


- Running the program
    1. The main() function is the entry point for the program
    2. Use a try except block to catch any errors & exceptions
    3. When the program catces the KeyboardInterrupt exception and stops excecution.
    4. The KeyboardInterrupt exception implies that the user presses Ctr + c or break
        before the program completes excecution.

    if __name__ == '__main__':
        try:
            main()
        except KeyboardInterrupt:
            abort()