from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class User:
    def __init__(self, username):
        self.username = username
        self.private_key = None
        self.public_key = None
        self.messages = []

    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()    

    def send_message(self, recipient, message):
        message_bytes = message.encode('utf-8') 
        encrypted_content = Message(self, recipient, message_bytes).encrypt_content()
        recipient.receive_message(self, encrypted_content)
    
    def receive_message(self, sender, encrypted_message):
        message = self.decrypt_message(encrypted_message)
        self.messages.append(message)

    def create_signature(self, message):
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, message, signature):
        try:
            self.public_key.verify(
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

class Message:
    def __init__(self, sender, recipient, content):
        self.sender = sender
        self.recipient = recipient
        self.content = content
        self.timestamp = None

    def encrypt_content(self):
        encrypted_content = self.recipient.public_key.encrypt(
            self.content,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_content

    def decrypt_content(self, recipient_private_key):
        decrypted_content = recipient_private_key.decrypt(
            self.content,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_content

def perform_key_exchange(user1, user2):
    user1.generate_key_pair()
    user2.generate_key_pair()


user1 = User("Alice")
user2 = User("Bob")

perform_key_exchange(user1, user2)

user1.send_message(user2, "Hello, Bob!")
user2.send_message(user1, "Hi, Alice!")

for user in [user1, user2]:
    print(f"{user.username}'s Messages:")
    for message in user.messages:
        decrypted_content = message.decrypt_content(user.private_key)
        print(f"From: {message.sender.username}, Content: {decrypted_content}")
