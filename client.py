import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import time
import base64
#################################################################
def receive_messages():
    print("receive_messages")
    while True:
        # print(not stop_event.is_set())
        # print("working")
        try:
            client_socket.settimeout(0.1)
            message = client_socket.recv(1024).decode('utf-8')
            client_socket.settimeout(None)
            message = decrypt_message(pvt_key_obj, message)
            print(message)
        except Exception as e:
            client_socket.settimeout(None)
            if stop_event.is_set():
                break
            # print(f"Error: {e}")
    print("receive_messages stopped")
def send_message():
    while True:
        recipient = input("username: ")
        stop_event.set()
        message = "request_public_key:"+recipient
        global receive_thread
        time.sleep(0.3)
        client_socket.send(message.encode('utf-8'))
        while True:
            try:
                pub_key=client_socket.recv(4096).decode('utf-8')
                break
            except Exception as e:
                print(f"Error: {e}")
                continue
        
        stop_event.clear()
        receive_thread = threading.Thread(target=receive_messages)
        receive_thread.start()
        if pub_key == "no_public_key":
            print(pub_key)
        elif pub_key == "user is offline":
            print(pub_key)
        else:
            print(pub_key)
            pub_key_obj = serialization.load_pem_public_key(
                pub_key.encode('utf-8'),
                backend=default_backend()
            )
            message = input("message: ")
            encrypted_message = encrypt_message(pub_key_obj, message)
            message_to_send = f"send:{recipient}:{base64.b64encode(encrypted_message).decode('utf-8')}"
            client_socket.send(message_to_send.encode('utf-8'))


def encrypt_message(public_key, message):
    message=message.encode('utf-8')
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
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

def check_pvt_key():
    file = open("private_key.txt", "+a")
    f_pvt_key = file.read()
    pvt_key = ""
    if len(f_pvt_key) < 1650:
        client_socket.send("no_pvt_key".encode('utf-8'))
        pvt_key = client_socket.recv(4096).decode('utf-8')
        file = open("private_key.txt", "w")
        file.write(pvt_key)
        file.close()
    else:
        client_socket.send("pvt_key".encode('utf-8'))
        pvt_key = file.read()
    global pvt_key_obj
    print(pvt_key)
    try:
        pvt_key_obj = serialization.load_pem_private_key(
            pvt_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        print(f"Error loading private key: {e}")
        
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
pvt_key_obj=None
receive_thread = threading.Thread(target=receive_messages)
stop_event = threading.Event()
flag=True
print("Welcome to the chatroom!")
menu()

