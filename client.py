import socket
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa


def check_key_validity():
    pass


def after_login(username):
    check_key_validity()
    print("To send a message, enter it in this format: recipient_username:message")
    while True:
        try:
            data = input()
            if len(data.split(':')) != 2:
                print("Invalid format.")
                continue
            recipient, message = data.split(':')
            
            # Use the private key of the sender to encrypt the message
            encrypted_message = pvt_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            client.send(f"message:{recipient}:{base64.b64encode(encrypted_message).decode('utf-8')}".encode('utf-8'))
        except Exception as e:
            print(f"Error: {e}")
            break

def login():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    client.send(f"login:{username}:{password}".encode('utf-8'))
    response = client.recv(1024).decode('utf-8')
    if response == "True":
        print("Login successful!")
        after_login(username)
    else:
        print("Login failed!")

def signup():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    re_password = input("Re-enter your password: ")
    if password != re_password:
        print("Passwords do not match.")
        signup()
    
    client.send(f"signup:{username}:{password}".encode('utf-8'))
    response = client.recv(1024).decode('utf-8')
    if response.split(':')[0] == "True":
        pvt_key_str = response.split(':')[1]
        pvt_key_bytes = base64.b64decode(pvt_key_str)
        pvt_key = serialization.load_pem_private_key(pvt_key_bytes,password=None, backend=default_backend())
        with open(f"{username}.txt", "w") as f:
            f.write(f"{username}:")
            f.write(f"{pvt_key}\n")
        print("Signup successful!")
        after_login(username)
    else:
        print("Signup failed!")

try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 12345))
except Exception as e:
    print(f"Error connecting to server: {e}")
    exit()

print("1. Login")
print("2. Register")
print("3. Exit")
while True:
    choice = int(input("Enter your choice: "))
    if choice == 1:
        login()
    elif choice == 2:
        signup()
    elif choice == 3:
        exit()
    else:
        print("Invalid choice.")
