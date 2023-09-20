import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import threading
import mysql.connector
import bcrypt
import base64

# Generate key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def handle_client(client, cursor):
    while True:
        try:
            data = client.recv(1024).decode('utf-8')
            data = data.split(':')
            if data[0] == 'signup':
                username = data[1]
                password = data[2]
                private_key, public_key = generate_key_pair()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                insert_query = "INSERT INTO users (username, password, public_key) VALUES (%s, %s, %s)"
                cursor.execute(insert_query, (username, hashed_password, public_pem))
                db.commit()
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                private_key_str = base64.b64encode(private_pem).decode('utf-8')
                client.send(f"True:{private_key_str}".encode('utf-8'))
            elif data[0] == 'login':
                username = data[1]
                password = data[2]
                query = "SELECT username, password FROM users WHERE username = %s"
                cursor.execute(query, (username,))
                user_data = cursor.fetchone()
                if user_data:
                    stored_username, stored_password = user_data
                    stored_password = stored_password.encode('utf-8')
                    if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                        print(f"Authentication successful. Username: {stored_username}")
                        client.send(f"True".encode('utf-8'))
                    else:
                        print(f"Authentication failed. Username: {stored_username}")
                        client.send(f"False".encode('utf-8'))
                else:
                    print(f"Authentication failed. Username: {username}")
                    client.send(f"False".encode('utf-8'))
            elif data[0] == 'message':
                sender_username = data[1]
                recipient_username = data[2]
                encrypted_message = data[3]
        except Exception as e:
            print(f"Error: {e}")
            break

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="mydatabase"
)
cursor = db.cursor()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 12345))
server.listen(5)
print("Server is listening for connections...")

while True:
    client, address = server.accept()
    print(f"Client {address} connected!")
    thread = threading.Thread(target=handle_client, args=(client, cursor))
    thread.start()
