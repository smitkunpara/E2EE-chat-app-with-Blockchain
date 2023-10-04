import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

pvt_key_obj=None

def send_message():
    while True:
        recipient = input("username: ")
        recipient = "request_public_key:"+recipient
        client_socket.send(recipient.encode('utf-8'))
        pub_key=client_socket.recv(1024).decode('utf-8')
        if pub_key == "no_public_key":
            print("User not found")
            send_message()
        else:
            pub_key_obj = serialization.load_pem_public_key(
                pub_key.encode('utf-8'),
                backend=default_backend()
            )
            message = input("message: ")
            message_to_send = f"send:{recipient}:{message}"
            message_to_send = encrypt_message(pub_key_obj, message_to_send)
            client_socket.send(message_to_send.encode('utf-8'))

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


def receive_messages():
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            message = decrypt_message(pvt_key_obj, message)
            print(message)
        except Exception as e:
            print(f"Error: {e}")
            break

def check_pvt_key():
    file = open("private_key.txt", "+a")
    f_pvt_key = file.read()
    pvt_key = ""
    if f_pvt_key == "" or len(f_pvt_key) != 2048:
        client_socket.send("no_pvt_key".encode('utf-8'))
        pvt_key = client_socket.recv(1024).decode('utf-8')
        file = open("private_key.txt", "w")
        file.write(pvt_key)
        file.close()
    else:
        client_socket.send("pvt_key".encode('utf-8'))
        pvt_key = file.read()
    global pvt_key_obj
    pvt_key_obj = serialization.load_pem_private_key(
        pvt_key.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    file.close()
    
        

def login():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    message_to_send = f"login:{username}:{password}"
    client_socket.send(message_to_send.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    if response == "login successful":
        check_pvt_key()
        print("Login successful")
        receive_thread = threading.Thread(target=receive_messages)
        receive_thread.start()
        send_message()
    else:
        print(response)
        menu()
        
        

def register():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    message_to_send = f"register:{username}:{password}"
    client_socket.send(message_to_send.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    if response == "register successful":
        check_pvt_key()
        print("Register successful")
        print("Login to continue")
        login()
    else:
        print(response)
        menu()

def menu():
    print("1. login")
    print("2. register")
    print("3. exit" )
    while True:
        choice = input("Enter your choice: ")
        if choice == "1":
            login()
            break
        elif choice == "2":
            register()
            break
        elif choice == "3":
            client_socket.close()
            break
        else:
            print("Invalid choice. Try again.")
###############################################################################
###############################################################################
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

print("Welcome to the chatroom!")
menu()

