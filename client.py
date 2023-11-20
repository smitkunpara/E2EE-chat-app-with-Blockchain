import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import time
import json,mysql.connector
import ssl


def reliable_send(ssl_client_socket,message):
    message = json.dumps(message)
    ssl_client_socket.send(message.encode('utf-8'))

def reliable_recv(ssl_client_socket):
    json_data = ""
    while True:
        try:
            json_data += ssl_client_socket.recv(1024).decode('utf-8')
            return json.loads(json_data)
        except ValueError:
            continue

def register_secondary_device():
    pass

def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def load_pvt_key():
    global my_username,my_password
    global pvt_key_obj
    with open("pvt_key.pem", "a+") as f:
        pass
    with open("pvt_key.pem", "r") as f:
        pvt_key_pem = f.read()
    if pvt_key_pem == "" or pvt_key_pem == None:
        pvt_key_obj = generate_private_key()
        pvt_key_pem = pvt_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption((my_username+my_password).encode('utf-8'))
        ).decode('utf-8')
        with open("pvt_key.pem", "w") as f:
            f.write(pvt_key_pem)
        public_key = pvt_key_obj.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        reliable_send(ssl_client_socket, ["update_public_key", my_username,public_key_pem])
        if reliable_recv(ssl_client_socket) != "public key updated":
            load_pvt_key()
    else:
        pvt_key_obj = serialization.load_pem_private_key(
            pvt_key_pem.encode('utf-8'),
            password=(my_username+my_password).encode('utf-8'),
            backend=default_backend()
        )

def send_message():
    print("type exit to exit")
    while True:
        message = input("Enter receiver username:")
        if message == "exit":
            global flag
            flag.set()
            break
        else:
            message = ["request_public_key", message[0]]
            reliable_send(ssl_client_socket,message)
        time.sleep(0.4)

def login():
    username = input("username: ")
    password = input("password: ")
    message = ["login", username, password]
    reliable_send(ssl_client_socket,message)
    response = reliable_recv(ssl_client_socket)
    if response == "login successful":
        global my_username
        global my_password
        my_username = username
        my_password = password
        load_pvt_key()
        receive_thread.start()
        print("login successful")
        send_message()
    else:
        print(response)
        menu()
     
def register():
    username = input("username: ")
    password = input("password: ")
    message = ["register", username, password]
    reliable_send(ssl_client_socket,message)
    response = reliable_recv(ssl_client_socket)
    if response == "register successful":
        print("login to continue")
        login()
    else:
        print(response)
        menu()

def receive_messages():
    while threading.Event().is_set() == False:
        try:
            message = reliable_recv(ssl_client_socket)
            message = pvt_key_obj.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')
            print(message)
        except Exception as e:
            print(f"Error: {e}")
            break
    
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
            ssl_client_socket.close()
            break
        else:
            print("Invalid choice. Try again.")

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="UROP"
)
cursor = db.cursor()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_verify_locations('C:/Users/smitk/OneDrive/programs/python/projects/UROP/server-cert.pem')

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_client_socket = context.wrap_socket(client_socket,server_hostname='smit')
ssl_client_socket.connect(('localhost', 12345))
pvt_key_obj = None
receive_thread = threading.Thread(target=receive_messages)
flag=threading.Event().clear()
my_username = None
second_device_pub_key = None
my_password = None
print("Connected to server")
menu()