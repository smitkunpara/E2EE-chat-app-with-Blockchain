import socket
import threading

clients = {}

def handle_client(client_socket, client_address, username):
    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            recipient, msg = message.split(':', 1)
            if recipient in clients:
                recipient_socket = clients[recipient]
                recipient_socket.send(f'{username}: {msg}'.encode('utf-8'))
            else:
                client_socket.send("Recipient not found.".encode('utf-8'))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        del clients[username]
        client_socket.close()

host = 'localhost'
port = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(5)

print(f"Server listening on {host}:{port}")

while True:
    client_socket, client_address = server_socket.accept()
    username = client_socket.recv(1024).decode('utf-8')
    clients[username] = client_socket
    print(f"Connection established with {username} at {client_address}")
    client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address, username))
    client_handler.start()
