from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def generate_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

def private_key_to_pem(private_key,username,password):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption((username+password).encode('utf-8'))
    )
    return pem

def public_key_to_pem(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def private_key_from_pem(pem,username,password):
    private_key = serialization.load_pem_private_key(
        pem.encode('utf-8'),
        password=(username+password).encode('utf-8'),
        backend=default_backend()
    )
    return private_key

def public_key_from_pem(pem):
    public_key = serialization.load_pem_public_key(
        pem.encode('utf-8'),
        backend=default_backend()
    )
    return public_key

def encrypt_message(public_key,message):
    encrypted_message = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message.hex()

def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        bytes.fromhex(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')


