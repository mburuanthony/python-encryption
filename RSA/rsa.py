import base64
from os import abort
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def toUtf8(s: bytes):
    """
    function to convert a string to utf8 standards
    """
    return str(s, 'utf-8')


# generate keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
public_key = private_key.public_key()


def write_keys_to_file():
    """
    function to save generated keys to respective files for later use 
    this is to avoid constantly generating new keys
    """
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
        f.close()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)
        f.close()


def use_private_key():
    """
    function to use a private key
    """
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    key_file.close()
    return private_key


def use_pub_key():
    """
    function to use a public key
    """
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    key_file.close()
    return public_key


def encrypt_plaintext(plaintext):
    """
    function to encrypt plain text
    @params: plaintext
    :encrypts the provided plaintext and returns an encrypted cipher text
    """
    encrypted = base64.b64encode(use_pub_key().encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))

    return encrypted


def decrypt_cipher(ciphertext):
    """
    function to decrypt cipher text
    @params: ciphertext
    :takes the ciphertext produced from the encrypt function and decrypts it 
    """
    decrypted = use_private_key().decrypt(
        base64.b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    """
    use toUtf8 function to convert the decrypted text to utf8 standard
    """
    decrypted_plaintext = toUtf8(decrypted)
    return decrypted_plaintext


def main():
    """ 
    start by generating keys (public and private) then saving them to file
    to avoid using different keys on every run, call the function -:write_keys_to_file():- once then comment it out
    """
    write_keys_to_file()

    # request user to input text to be encrypted
    plain_text = str(input("Enter Plain Text to encrypt :\t"))

    # encrypt provided text
    cipher_text = encrypt_plaintext(plaintext=plain_text.encode())
    # decrypt encrypted text
    decrypted_text = decrypt_cipher(ciphertext=cipher_text)

    print(f"PLAIN TEXT : {plain_text}")
    print(f"CIPHER TEXT : {cipher_text}")
    print(f"DECRYPTED TEXT : {decrypted_text}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        abort()
