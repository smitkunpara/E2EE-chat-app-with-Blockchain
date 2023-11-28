# Chat Application with Blockchain Integration

## Overview

This project is a end to end chat application implemented in Python, incorporating blockchain technology for user Authentication and key management. The application allows users to register, log in securely, send encrypted messages, and update their public keys. The underlying blockchain ensures the integrity and security of user data.

## Features

<!-- - **User Registration**: Users can register with a unique username and password, which is securely stored on a blockchain.

- **Login and Authentication**: Secure login mechanism using hashed passwords. Passwords are never transmitted in plaintext. -->

<!-- talk about login and registeration -->
- **User Authentication**: Users can register with a unique username and password, which is securely stored on a blockchain. And login with their credentials.
- **Public Key Management**: Both private and public keys play a crucial role in secure communication. Users can leverage their private keys to decrypt incoming messages and use recipients' public keys to encrypt outgoing messages, ensuring end-to-end encryption.

- **Encrypted Messaging**: Messages are encrypted using the recipient's public key, ensuring confidentiality.

- **Blockchain Integration**: User data is stored on a blockchain, providing a decentralized and tamper-resistant data storage solution.

## Prerequisites

- Python 3.x
- Ethereum Node (for blockchain integration)
- MySQL Database with the following tables:
    - `users` (username, password, pub_key, update_time)
- SSL self-certificate (Install using: `openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -x509 -days 365 -out server-cert.pem`)

## Setup

1. Create a new file named `.env` in the project directory.
2. Create a new file named `.env` and add following variables and enter your values:

    ```env
    CONTRACT_ADDRESS=0xA1B2C3D4..
    ACCOUNT=0x0xA1B2C3D4..
    PRIVATE_KEY=0x0xA1B2C3D4..
    ```
4. Configure Ethereum node and update the blockchain contract address and account details in `blockchain.py`.
5. Set up MySQL database and update connection details in the server script.

## Usage

1. Run the server: `python server.py`
2. Run the client: `python client.py`
3. Follow the on-screen instructions to register, log in, and send encrypted messages.