import socket
import ssl
import threading
import mysql.connector
import json
from blockchain import *
import time
import hashlib

def reliable_send(ssl_client_socket,message):
    message = json.dumps(message)
    ssl_client_socket.send(message.encode('utf-8'))

def reliable_recv(ssl_client_socket):
    json_data = ""
    while True:
        try:
            json_data += ssl_client_socket.recv(1024).decode('utf-8')
            if not json_data:
                raise ConnectionResetError("connection closed")
            return json.loads(json_data)
        except ValueError:
            continue

def register(message):
    data=get_user_data(message[1])
    if data[0]=="" and data[0]=="":
        result = set_user_data(message[1],hashlib.md5(message[2].encode()).hexdigest())
        if result != None:
            return "register successful"
        else:
            return "register failed"
    else:
        return "User already exists"
        
    # queary = f"SELECT * FROM users WHERE username = '{message[1]}'"
    # cursor.execute(queary)
    # rows = cursor.fetchall()
    # if len(rows) == 0 or rows==None:
    #     queary = f"INSERT INTO users (username, password) VALUES ('{message[1]}', '{hashlib.md5(message[2].encode()).hexdigest()}')"
    #     cursor.execute(queary)
    #     db.commit()
    #     return "register successful"
    # else:
    #     return "User already exists"

def login(message):
    data=get_user_data(message[1])
    if data[0]=="" and data[1]=="":
        return "",False,"User not found"
    else:
        if data[1] == hashlib.md5(message[2].encode()).hexdigest():
            online_users[message[1]] = ssl_client_socket
            return message[1],True,"login successful"
        else:
            return "",False,"Incorrect password"
    # queary = f"SELECT * FROM users WHERE username = '{message[1]}'"
    # cursor.execute(queary)
    # rows = cursor.fetchall()
    # if len(rows) == 0 or rows==None:
    #     return False,"User not found"
    # else:
    #     if rows[0][1] == hashlib.md5(message[2].encode()).hexdigest():
    #         online_users[message[1]] = ssl_client_socket
    #         return message[1],True,"login successful"
    #     else:
    #         return "",False,"Incorrect password"

def request_public_key(message,is_logged_in):
    if is_logged_in==False:
        return "Please login first"
    data=get_user_data(message[1])
    if data[0]=="" and data[0]=="":
        return "User not found"
    else:
        return ["requested_pub_key",message[1],data[2]]
    # if message[1] not in online_users:
    #     return "user is offline"
    # else:
    #     queary = f"SELECT * FROM users WHERE username = '{message[1]}'"
    #     cursor.execute(queary)
    #     rows = cursor.fetchall()
    #     print(["requested_pub_key",message[1],rows[0][2]])
    #     return ["requested_pub_key",message[1],rows[0][2]]

def send_message(username,message, is_logged_in):
    if is_logged_in==True:
        if message[1] in online_users:
            ssl_client_socket = online_users[message[1]]
            reliable_send(ssl_client_socket, ["message_received", username,message[2]])
            return "Message sent"
        else:
            return "User is offline or does not exist"
    else:
        return "Please login first"

def update_public_key(message,is_logged_in):
    if is_logged_in==True:
        update_user_data(message[1],message[2],int(str(time.time()).replace(".", "")))
        return "public key updated"
    else:
        return "Please login first"
    # queary=f"UPDATE users SET pub_key = '{message[2]}' , update_time = NOW() WHERE username = '{message[1]}'"
    # cursor.execute(queary)
    # db.commit()
    # return "public key updated"

def logout(username):
    online_users.pop(username)
    return "",False,["logout successful"]

def handle_client(ssl_client_socket):
    is_logged_in = False
    username = ""
    while True:
        try:
            message = reliable_recv(ssl_client_socket)
            print(message)
            if message[0] == "register":
                message_result = register(message)
            elif message[0] == "login":
                username,is_logged_in,message_result = login(message)
            elif message[0] == "update_public_key":
                message_result=update_public_key(message,is_logged_in)
            elif message[0] == "request_public_key":
                message_result = request_public_key(message, is_logged_in)
            elif message[0] == "send_message":
                message_result = send_message(username,message, is_logged_in)
            elif message[0] == "logout":
                username,is_logged_in,message_result = logout(username)
            else:
                print("Invalid message")
            reliable_send(ssl_client_socket,message_result)
        except ConnectionResetError:
            print(f"Connection from {client_address} has been closed.")
            if username != "":
                username,is_logged_in,message_result = logout(username)
            break
            

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="UROP"
)
cursor = db.cursor()

host = '10.1.166.113'
port = 1234

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host, port))
server_socket.listen(5)
online_users = {}
print(f"Server listening on {host}:{port}")

while True:
    client_socket, client_address = server_socket.accept()
    ssl_client_socket = context.wrap_socket(client_socket, server_side=True)
    print(f"Connection from {client_address} has been established.")
    client_thread = threading.Thread(target=handle_client, args=(ssl_client_socket,))
    client_thread.start()        