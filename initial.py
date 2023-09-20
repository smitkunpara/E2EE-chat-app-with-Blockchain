from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Generate key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt a message
def encrypt_message(public_key, message):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

# Decrypt a message
def decrypt_message(private_key, encrypted_message):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

# Create digital signature
def create_signature(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify digital signature
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Simulate key exchange
def perform_key_exchange():
    private_key, public_key = generate_key_pair()

    message = b"Hello World!"
    encrypted_message = encrypt_message(public_key, message)
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(decrypted_message)
    signature = create_signature(private_key, message)
    is_valid = verify_signature(public_key, message, signature)
    print(is_valid)

    return private_key, public_key

def simulate_messaging():
    sender_message = b"Hello World!"
    sender_signature = create_signature(sender_private_key, sender_message)
    recipient_message = b"Hello World!"
    is_valid = verify_signature(sender_public_key, recipient_message, sender_signature)
    print(is_valid)
    

sender_private_key, sender_public_key = perform_key_exchange()
recipient_private_key, recipient_public_key = perform_key_exchange()
simulate_messaging()
