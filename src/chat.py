"""
Implementation of a simple end to end encrypted chat
"""

import socket
import threading
import json
from rsa_oaep import RSA_OAEP

# generating keys
rsa_instance = RSA_OAEP(2048)
public_key, private_key = rsa_instance.generate_keypair()
partner_key = None

choice = input("Do you want to host (1) or to connect (2): ")

if choice == '1':
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("192.168.86.25",9999))         # use your local IP address on host machine
    server.listen()

    client, _ = server.accept()
    
    # Exchange public key with chat partner

    # sending the key
    public_key_json = json.dumps(public_key)    # our implemetation of RSA does not support pem so we sent by json
    client.send(public_key_json.encode())

    # Receiving the key
    data = client.recv(2048).decode()
    partner_key = tuple(json.loads(data))
elif choice == '2':
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("192.168.86.25",8888))      # use your local IP address on host machine

    # Receiving the key
    data = client.recv(2048).decode()
    partner_key = tuple(json.loads(data))

    # sending the key
    public_key_json = json.dumps(public_key)
    client.send(public_key_json.encode())
else:
    exit()

def send_message(c):
    while True:
        message = input("")

        encrypted_mesage = rsa_instance.encrypt_string(message, partner_key)

        c.send(json.dumps(encrypted_mesage).encode())
        print("You: " + message)


def receive_message(c):
    while True:
        receive = c.recv(2048).decode()
        message = rsa_instance.decrypt_string(json.loads(receive), private_key)

        print("Your friend: " + message)


threading.Thread(target=send_message, args=(client, )).start()
threading.Thread(target=receive_message, args=(client, )).start()