import tkinter as tk
import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import json
import ssl

def reliable_send(message):
    global ssl_client_socket
    message = json.dumps(message)
    ssl_client_socket.send(message.encode('utf-8'))

def reliable_recv():
    global ssl_client_socket
    json_data = ""
    while True:
        try:
            json_data += ssl_client_socket.recv(1024).decode('utf-8')
            return json.loads(json_data)
        except ValueError:
            continue

def pack_widgets():
    login_button.pack(pady=10)
    register_button.pack(pady=10)

    login_label.pack(pady=10)
    login_message_label.pack(pady=5)
    login_username_label.pack(pady=2)
    login_username_entry.pack(pady=5)
    login_password_label.pack(pady=2)
    login_password_entry.pack(pady=5)
    login_submit_button.pack(pady=10)
    back_to_login_button.pack(pady=10)

    register_label.pack(pady=10)
    register_message_label.pack(pady=5)
    register_username_label.pack(pady=2)
    register_username_entry.pack(pady=5)
    register_password_label.pack(pady=2)
    register_password_entry.pack(pady=5)
    register_submit_button.pack(pady=10)
    back_to_register_button.pack(pady=10)

    chat_label.pack(pady=10)
    chat_message_label.pack(pady=5)
    message_display.pack(pady=10)
    username_label.pack(side=tk.LEFT, padx=5)
    username_entry.pack(side=tk.LEFT, padx=5)
    message_label.pack(side=tk.RIGHT, padx=5)
    chat_entry.pack(side=tk.RIGHT, padx=5)
    send_button.pack(pady=10)
    logout_button.pack(pady=10)
    second_device_button.pack(pady=10)
    device_code_label.pack(pady=2)
    device_code_entry.pack(pady=5)
    submit_data_button.pack(pady=10)
    second_device_button.pack(pady=10)

def encrypt_message(public_key_pem):
    global user_message
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    encrypted_message = public_key.encrypt(
        user_message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def decrypt_message(ciphertext):
    plaintext = pvt_key_obj.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

def show_login():
    switch_frame(login_frame)
    clear_login_form()

def show_register():
    switch_frame(register_frame)
    clear_register_form()

def show_initial():
    switch_frame(initial_frame)

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
        reliable_send(["update_public_key", my_username,public_key_pem])
        if reliable_recv() != "public key updated":
            load_pvt_key()
    else:
        pvt_key_obj = serialization.load_pem_private_key(
            pvt_key_pem.encode('utf-8'),
            password=(my_username+my_password).encode('utf-8'),
            backend=default_backend()
        )
        
def register_user():
    username = register_username_entry.get()
    password = register_password_entry.get()
    
    if username and password:
        message = ["register", username, password]
        reliable_send(message)
        response = reliable_recv()
        if response == "register successful":
            switch_frame(login_frame)
            clear_register_form()
            login_message_label.config(text="Registration successful login to continue", fg="green")
        else:
            register_message_label.config(text=response, fg="red")

    else:
        register_message_label.config(text="Please enter both username and password", fg="red")

def login():
    username = login_username_entry.get()
    password = login_password_entry.get()
    message = ["login", username, password]
    reliable_send(message)
    response = reliable_recv()
    if response == "login successful":
        global my_username
        global my_password
        my_username = username
        my_password = password
        load_pvt_key()
        receive_thread.start()
        switch_frame(chat_frame)
    else:
        login_message_label.config(text=response, fg="red")

def send_message():
    username = username_entry.get()
    message = chat_entry.get()
    chat_entry.delete(0, tk.END)
    if username and message:
        if username in users_pub_key:
            encrypted_message = encrypt_message(users_pub_key[username])
            reliable_send(["send_message", my_username, username, encrypted_message.hex()])
            message_display.config(state=tk.NORMAL)
            message_display.insert(tk.END, f"YOU: {message}\n")
            message_display.config(state=tk.DISABLED)
        else:
            reliable_send(["request_public_key", username])
            global user_message
            user_message = message
    else:
        print("Please enter both username and message.")

def receive_messages():
    global flag
    while flag==True:
        try:
            message = reliable_recv()
            if message[0] == "requested_pub_key":
                global user_message
                users_pub_key[message[1]] = message[2]
                public_key_obj = serialization.load_pem_public_key(
                    message[2].encode('utf-8'),
                    backend=default_backend()
                )
                encrypted_message = public_key_obj.encrypt(
                    user_message.encode('utf-8'),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                reliable_send(["send_message", my_username, encrypted_message.hex()])

            elif message[0] == "message_received":
                message_display.config(state=tk.NORMAL)
                message_display.insert(tk.END, f"{decrypt_message(bytes.fromhex(message[1]))}\n")
                message_display.config(state=tk.DISABLED)
            else:
                message_display.config(state=tk.NORMAL)
                message_display.insert(tk.END, f"{message}\n")
                message_display.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Error: {e}")          

def logout():
    global my_username,my_password,pvt_key_obj,flag
    my_username = my_password = pvt_key_obj = None
    flag=False
    switch_frame(initial_frame)

def register_second_device():
    entered_device_code = device_code_entry.get()
    verification_code = "this0358902fd"
    if entered_device_code == verification_code:
        switch_frame(chat_frame)
        chat_message_label.config(text="Second device added successfully", fg="green")
    else:
        print("Invalid device code")

def switch_frame(frame):
    login_message_label.config(text="")
    register_message_label.config(text="")
    global current_frame
    current_frame.pack_forget()
    current_frame = frame
    current_frame.pack()

def show_second_device_input():
    switch_frame(second_device_frame)
    
def clear_login_form():
    login_username_entry.delete(0, tk.END)
    login_password_entry.delete(0, tk.END)

def clear_register_form():
    register_username_entry.delete(0, tk.END)
    register_password_entry.delete(0, tk.END)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_verify_locations('C:/Users/smitk/OneDrive/programs/python/projects/UROP/server-cert.pem')

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_client_socket = context.wrap_socket(client_socket,server_hostname='smit')
ssl_client_socket.connect(('localhost', 12345))
pvt_key_obj = None
receive_thread = threading.Thread(target=receive_messages)
flag=True
my_username = None
second_device_pub_key = None
my_password = None
users_pub_key = {}

root = tk.Tk()
root.title("Chat Application")

# Frames
initial_frame = tk.Frame(root)
login_frame = tk.Frame(root)
register_frame = tk.Frame(root)
chat_frame = tk.Frame(root)
second_device_frame = tk.Frame(root)

current_frame = initial_frame
current_frame.pack()

# Buttons
login_button = tk.Button(initial_frame, text="Login", command=show_login)
register_button = tk.Button(initial_frame, text="Register", command=show_register)

# Labels
login_label = tk.Label(login_frame, text="Login")
register_label = tk.Label(register_frame, text="Register")
chat_label = tk.Label(chat_frame, text="Chat Room")

# Entry Widgets
login_username_entry = tk.Entry(login_frame, width=20)
login_password_entry = tk.Entry(login_frame, width=20, show='*')

register_username_entry = tk.Entry(register_frame, width=20)
register_password_entry = tk.Entry(register_frame, width=20, show='*')

# Labels for Username and Password
login_username_label = tk.Label(login_frame, text="Username:")
login_password_label = tk.Label(login_frame, text="Password:")

register_username_label = tk.Label(register_frame, text="Username:")
register_password_label = tk.Label(register_frame, text="Password:")

# Labels
login_message_label = tk.Label(login_frame, text="", fg="red")
register_message_label = tk.Label(register_frame, text="", fg="red")
username_label = tk.Label(chat_frame, text="Enter username:")
message_label = tk.Label(chat_frame, text="Enter message:")
chat_message_label = tk.Label(chat_frame, text="",fg="red")

# Entry Widgets
username_entry = tk.Entry(chat_frame, width=20)
chat_entry = tk.Entry(chat_frame, width=50)
device_code_label = tk.Label(second_device_frame, text="Enter Device Code:")
device_code_entry = tk.Entry(second_device_frame, width=20)

# Buttons
login_submit_button = tk.Button(login_frame, text="Submit", command=login)
register_submit_button = tk.Button(register_frame, text="Submit", command=register_user)
send_button = tk.Button(chat_frame, text="Send", command=send_message)
logout_button = tk.Button(chat_frame, text="Logout", command=logout)
back_to_login_button = tk.Button(login_frame, text="Back", command=show_initial)
back_to_register_button = tk.Button(register_frame, text="Back", command=show_initial)
second_device_button = tk.Button(chat_frame, text="Add Second Device", command=show_second_device_input)
submit_data_button = tk.Button(second_device_frame, text="Submit Data", command=register_second_device)


# Message Display
message_display = tk.Text(chat_frame, height=20, width=70)
message_display.config(state=tk.DISABLED)

# Packing widgets
pack_widgets()
root.mainloop()

user_message=""
