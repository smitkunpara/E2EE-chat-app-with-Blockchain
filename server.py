import socket
import threading
import mysql.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import random
import string

connected_clients = {}
online_users = {}

def genereate_random_string(length):
    letters = string.ascii_lowercase
    str=''.join(random.choice(letters) for i in range(length))
    if str in connected_clients:
        return genereate_random_string(length)
    return str
    

def generate_key_pair(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_pem_str = public_key_pem.decode('utf-8')
    global db, cursor
    queary=f"UPDATE users SET pub_key = '{public_key_pem_str}' WHERE username = '{username}'"
    cursor.execute(queary)
    db.commit()
    return private_key

def register(message):
    queary = f"SELECT * FROM users WHERE username = '{message[1]}'"
    cursor.execute(queary)
    rows = cursor.fetchall()
    print("rows:",rows)
    if len(rows) == 0 or rows==None:
        queary = f"INSERT INTO users (username, password) VALUES ('{message[1]}', '{message[2]}')"
        cursor.execute(queary)
        db.commit()
        client_socket.send("register successful".encode('utf-8'))
    else:
        client_socket.send("register failed".encode('utf-8'))

def request_public_key(message):
    queary = f"SELECT * FROM users WHERE username = '{message[1]}'"
    cursor.execute(queary)
    rows = cursor.fetchall()
    if len(rows) == 0:
        client_socket.send("no_public_key".encode('utf-8'))
    else:
        client_socket.send(rows[2].encode('utf-8'))

def send(message):
    recipient = message[1]
    message = message[2]
    recipient_socket = online_users[recipient]
    recipient_socket.send(message.encode('utf-8'))


def no_pvt_key(username):
    private_key=generate_key_pair(username)
    print("pvt key",private_key)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print("pem key",private_key_pem.decode('utf-8'))
    private_key_pem_str = private_key_pem.decode('utf-8')
    online_users[username].send(private_key_pem_str.encode('utf-8'))

def handle_client(client_socket, client_address,username):
    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            message=message.split(":")
            print(message)
            global cursor
            global db
            if message[0]=="login":
                queary = f"SELECT * FROM users WHERE username = '{message[1]}' AND password = '{message[2]}'"
                print(queary)
                cursor.execute(queary)
                rows = cursor.fetchall()
                if len(rows) == 0:
                    client_socket.send("login failed".encode('utf-8'))
                else:
                    username=message[1]
                    online_users[username]=client_socket
                    client_socket.send("login successful".encode('utf-8'))
                    
    
            elif message[0]=="register":
                register(message)
            elif message[0]=="request_public_key":
                request_public_key(message)
            elif message[0]=="send":
                send(message)
            elif message[0]=="no_pvt_key":
                no_pvt_key(username)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print(connected_clients)
        print(online_users)
        online_users.pop(username)
        client_socket.close()

#####################################################
#####################################################
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="UROP"
)
cursor = db.cursor()

host = 'localhost'
port = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(5)

print(f"Server listening on {host}:{port}")

while True:
    client_socket, client_address = server_socket.accept()
    newclient=genereate_random_string(10)
    connected_clients[newclient]=client_socket

    client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address,newclient))
    client_handler.start()

