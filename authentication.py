import subprocess
import socket
import psutil
import requests
import time
from urllib3.exceptions import NewConnectionError, MaxRetryError
import mysql.connector
import bcrypt
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="mydatabase"
)
cursor = db.cursor()

def create_account(username, password):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=os.urandom
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert user data into the database and get the user's ID
    insert_query = "INSERT INTO users (username, password, private_key, public_key) VALUES (%s, %s, %s, %s)"
    cursor.execute(insert_query, (username, hashed_password, private_pem, public_pem))
    db.commit()

def authenticate(username, password):
    query = "SELECT username, password FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    user_data = cursor.fetchone()

    if user_data:
        stored_username, stored_password = user_data
        stored_password = stored_password.encode('utf-8')
        
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            print(f"Authentication successful. Usernmae: {stored_username}")
            return True
        else:
            print("Authentication failed. Incorrect password.")
            return False
    else:
        print("User does not exist. Would you like to create an account? (y/n)")
        create_option = input()
        if create_option.lower() == 'y':
            create_account(username, password)
            print("Account created successfully.")
        return False


username = input("Enter your username: ")
password = input("Enter your password: ")
print("--",password.encode('utf-8'))

if authenticate(username, password):
    print("Welcome!")
    connection_check()

db.close()
