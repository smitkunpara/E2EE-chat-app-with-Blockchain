import socket
import threading
import mysql.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

online_clients = {}

def generate_key_pair(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    global db, cursor
    queary=f"UPDATE users SET public_key = {public_key} WHERE username = {username}"
    cursor.execute(queary)
    db.commit()
    return private_key

def handle_client(client_socket, client_address, username):
    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            message=message.split(":")
            global cursor
            global db
            if message[0]=="login":
                queary = f"SELECT * FROM users WHERE username = {message[1]} AND password = {message[2]}"
                cursor.execute(queary)
                rows = cursor.fetchall()
                if len(rows) == 0:
                    client_socket.send("login failed".encode('utf-8'))
                client_socket.send("login successful".encode('utf-8'))
            elif message[0]=="register":
                queary = f"SELECT * FROM users WHERE username = {message[1]}"
                cursor.execute(queary)
                rows = cursor.fetchall()
                if len(rows) == 0:
                    queary = f"INSERT INTO users (username, password,pub_key) VALUES ({message[1]}, {message[2]},None)"
                    cursor.execute(queary)
                    db.commit()
                    client_socket.send("register successful".encode('utf-8'))
                else:
                    client_socket.send("register failed".encode('utf-8'))
            elif message[0]=="request_public_key":
                queary = f"SELECT * FROM users WHERE username = {message[1]}"
                cursor.execute(queary)
                rows = cursor.fetchall()
                if len(rows) == 0:
                    client_socket.send("no_public_key".encode('utf-8'))
                else:
                    client_socket.send(rows[2].encode('utf-8'))
            elif message[0]=="send":
                recipient = message[1]
                message = message[2]
                recipient_socket = online_clients[recipient]
                recipient_socket.send(message.encode('utf-8'))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        del online_clients[username]
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
    username = client_socket.recv(1024).decode('utf-8')
    online_clients[username] = client_socket
    print(f"Connection established with {username} at {client_address}")
    client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address, username))
    client_handler.start()

