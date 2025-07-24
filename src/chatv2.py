"""
Improved version of end-to-end encrypted chat with message authentication using HMAC
"""
import socket
import threading
import json
import hmac
import hashlib
import os
from rsa_oaep import RSA_OAEP

class SecureChat:
    def __init__(self):
        # Generate RSA keys
        self.rsa_instance = RSA_OAEP(2048)
        self.public_key, self.private_key = self.rsa_instance.generate_keypair()
        self.partner_key = None
        self.hmac_key = None
        self.socket = None
        self.client_socket = None
        
    def get_local_ip(self):
        """Get the local IP address automatically"""
        try:
            # Create a socket to connect to a remote address (doesn't actually connect)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google's DNS server
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            # Fallback method
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
    
    def generate_hmac_key(self):
        """Generate a random HMAC key"""
        return os.urandom(32)  # 256-bit key
    
    def create_hmac(self, message, key):
        """Create HMAC for message authentication"""
        return hmac.new(key, message.encode('utf-8'), hashlib.sha256).hexdigest()
    
    def verify_hmac(self, message, received_hmac, key):
        """Verify HMAC to authenticate message"""
        expected_hmac = self.create_hmac(message, key)
        return hmac.compare_digest(expected_hmac, received_hmac)
    
    def send_message_with_length(self, sock, data):
        """Send message with length prefix for proper framing"""
        message = data.encode('utf-8')
        length = len(message)
        sock.send(length.to_bytes(4, 'big') + message)
    
    def receive_message_with_length(self, sock):
        """Receive message with length prefix"""
        try:
            # Receive length first
            length_bytes = b''
            while len(length_bytes) < 4:
                chunk = sock.recv(4 - len(length_bytes))
                if not chunk:
                    return None
                length_bytes += chunk
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Receive the actual message
            message = b''
            while len(message) < length:
                chunk = sock.recv(length - len(message))
                if not chunk:
                    return None
                message += chunk
                
            return message.decode('utf-8')
        except Exception as e:
            print(f"Error receiving message: {e}")
            return None
    
    def exchange_keys(self, sock, is_host=True):
        """Exchange public keys and establish HMAC key"""
        try:
            if is_host:
                # Host sends public key first
                public_key_json = json.dumps(self.public_key)
                self.send_message_with_length(sock, public_key_json)
                
                # Receive partner's public key
                data = self.receive_message_with_length(sock)
                if data:
                    self.partner_key = tuple(json.loads(data))
                
                # Generate and send HMAC key (encrypted with partner's public key)
                self.hmac_key = self.generate_hmac_key()
                encrypted_hmac_key = self.rsa_instance.encrypt_string(
                    self.hmac_key.hex(), public_key=self.partner_key
                )
                self.send_message_with_length(sock, json.dumps(encrypted_hmac_key))
                
            else:
                # Client receives public key first
                data = self.receive_message_with_length(sock)
                if data:
                    self.partner_key = tuple(json.loads(data))
                
                # Send public key
                public_key_json = json.dumps(self.public_key)
                self.send_message_with_length(sock, public_key_json)
                
                # Receive HMAC key (encrypted with our public key)
                data = self.receive_message_with_length(sock)
                if data:
                    encrypted_hmac_key = json.loads(data)
                    hmac_key_hex = self.rsa_instance.decrypt_string(
                        encrypted_hmac_key, private_key=self.private_key
                    )
                    self.hmac_key = bytes.fromhex(hmac_key_hex)
            
            print("✅ Key exchange completed successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Key exchange failed: {e}")
            return False
    
    def start_host(self, port=9999):
        """Start as host/server"""
        local_ip = self.get_local_ip()
        print(f"🖥️  Starting server on {local_ip}:{port}")
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((local_ip, port))
            self.socket.listen(1)
            
            print(f"⏳ Waiting for connection on {local_ip}:{port}...")
            self.client_socket, addr = self.socket.accept()
            print(f"✅ Connected to {addr[0]}:{addr[1]}")
            
            # Exchange keys
            if self.exchange_keys(self.client_socket, is_host=True):
                self.start_chat_threads()
            else:
                print("❌ Failed to establish secure connection")
                
        except Exception as e:
            print(f"❌ Server error: {e}")
        finally:
            self.cleanup()
    
    def connect_to_host(self, host_ip, port=9999):
        """Connect to host/server"""
        print(f"🔗 Connecting to {host_ip}:{port}...")
        
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host_ip, port))
            print(f"✅ Connected to {host_ip}:{port}")
            
            # Exchange keys
            if self.exchange_keys(self.client_socket, is_host=False):
                self.start_chat_threads()
            else:
                print("❌ Failed to establish secure connection")
                
        except Exception as e:
            print(f"❌ Connection error: {e}")
        finally:
            self.cleanup()
    
    def start_chat_threads(self):
        """Start sending and receiving threads"""
        print("\n🚀 Secure chat started! Type your messages below:")
        print("💡 Press Ctrl+C to exit\n")
        
        # Start threads for sending and receiving
        send_thread = threading.Thread(target=self.send_messages)
        receive_thread = threading.Thread(target=self.receive_messages)
        
        send_thread.daemon = True
        receive_thread.daemon = True
        
        send_thread.start()
        receive_thread.start()
        
        try:
            send_thread.join()
        except KeyboardInterrupt:
            print("\n👋 Exiting chat...")
    
    def send_messages(self):
        """Handle sending messages"""
        while True:
            try:
                message = input("")
                if not message.strip():
                    continue
                
                # Encrypt the message first
                encrypted_message = self.rsa_instance.encrypt_string(message, public_key=self.partner_key)
                
                # Suppose an attacker intercept our connection and send a tampoered_message.
                tampered_message = self.rsa_instance.encrypt_string("send me 100 dollar please", public_key=self.partner_key)

                # Create HMAC for the original message (before encryption)
                message_hmac = self.create_hmac(message, self.hmac_key)
                
                # Create payload with encrypted message and HMAC (NO plaintext!)
                payload = {
                    'encrypted_message': encrypted_message,
                    'hmac': message_hmac
                }
                
                # Send the payload
                self.send_message_with_length(self.client_socket, json.dumps(payload))
                print(f"You: {message}")
                
            except Exception as e:
                print(f"❌ Error sending message: {e}")
                break
    
    def receive_messages(self):
        """Handle receiving messages"""
        while True:
            try:
                # Receive the payload
                data = self.receive_message_with_length(self.client_socket)
                if not data:
                    print("❌ Connection lost")
                    break
                
                payload = json.loads(data)
                encrypted_message = payload['encrypted_message']
                received_hmac = payload['hmac']
                
                # Decrypt the message first
                decrypted_message = self.rsa_instance.decrypt_string(
                    encrypted_message, private_key=self.private_key
                )
                
                # Then verify HMAC using the decrypted message
                if self.verify_hmac(decrypted_message, received_hmac, self.hmac_key):
                    print(f"Friend: {decrypted_message}")
                else:
                    print("⚠️  WARNING: Message authentication failed! Message may be tampered.")
                    print(f"Friend (UNVERIFIED): {decrypted_message}")
                
            except Exception as e:
                print(f"❌ Error receiving message: {e}")
                break
    
    def demo_hmac_verification(self):
        """Demo HMAC verification with tampered messages"""
        print("\n🧪 HMAC VERIFICATION DEMO")
        print("=" * 50)
        
        # Generate demo keys
        self.hmac_key = self.generate_hmac_key()
        
        # Test 1: Valid message
        print("Test 1: Valid Message")
        test_message = "Hello, this is a secure message!"
        hmac_value = self.create_hmac(test_message, self.hmac_key)
        is_valid = self.verify_hmac(test_message, hmac_value, self.hmac_key)
        print(f"Message: '{test_message}'")
        print(f"HMAC: {hmac_value[:20]}...")
        print(f"Verification: {'✅ VALID' if is_valid else '❌ INVALID'}")
        print()
        
        # Test 2: Tampered message (same HMAC)
        print("Test 2: Tampered Message (attacker changed message)")
        tampered_message = "Hello, this is a TAMPERED message!"
        is_valid_tampered = self.verify_hmac(tampered_message, hmac_value, self.hmac_key)
        print(f"Original: '{test_message}'")
        print(f"Tampered: '{tampered_message}'")
        print(f"Using original HMAC: {hmac_value[:20]}...")
        print(f"Verification: {'✅ VALID' if is_valid_tampered else '❌ INVALID (Expected)'}")
        print()
        
        # Test 3: Wrong HMAC key
        print("Test 3: Wrong HMAC Key (attacker doesn't know key)")
        wrong_key = self.generate_hmac_key()
        wrong_hmac = self.create_hmac(test_message, wrong_key)
        is_valid_wrong_key = self.verify_hmac(test_message, wrong_hmac, self.hmac_key)
        print(f"Message: '{test_message}'")
        print(f"HMAC with wrong key: {wrong_hmac[:20]}...")
        print(f"Verification with correct key: {'✅ VALID' if is_valid_wrong_key else '❌ INVALID (Expected)'}")
        print()
        
        # Test 4: Demonstrate HMAC prevents modification
        print("Test 4: Show HMAC protects against message modification")
        messages = [
            "Transfer $10 to Alice",
            "Transfer $1000 to Alice",  # Attacker tries to change amount
            "Transfer $10 to Bob"       # Attacker tries to change recipient
        ]
        
        original_hmac = self.create_hmac(messages[0], self.hmac_key)
        print(f"Original authorized message: '{messages[0]}'")
        print(f"HMAC: {original_hmac[:20]}...")
        print()
        
        for i, msg in enumerate(messages[1:], 1):
            valid = self.verify_hmac(msg, original_hmac, self.hmac_key)
            print(f"Attacker tries: '{msg}'")
            print(f"Using original HMAC: {'✅ ACCEPTED' if valid else '❌ REJECTED (Good!)'}")
            print()
        
        print("🎯 DEMO CONCLUSIONS:")
        print("• HMAC successfully detects message tampering")
        print("• Changing even one character breaks authentication")
        print("• Attackers cannot forge valid HMACs without the key")
        print("• This prevents man-in-the-middle attacks on messages")
        print("=" * 50)

    def cleanup(self):
        """Clean up resources"""
        try:
            if self.client_socket:
                self.client_socket.close()
            if self.socket:
                self.socket.close()
        except:
            pass

def main():
    chat = SecureChat()
    local_ip = chat.get_local_ip()
    
    print("🔐 Secure End-to-End Encrypted Chat")
    print("=" * 40)
    print(f"📍 Your local IP: {local_ip}")
    print()
    
    while True:
        choice = input("Choose an option:\n1. Host (wait for connection)\n2. Connect to someone\n3. Demo HMAC verification\n\nChoice (1/2/3): ").strip()
        
        if choice == '1':
            port = input(f"Enter port (default 9999): ").strip()
            port = int(port) if port else 9999
            print(f"\n📋 Share this with your friend: {local_ip}:{port}")
            print("=" * 40)
            chat.start_host(port)
            break
            
        elif choice == '2':
            host_input = input(f"Enter host IP:port (or just IP for port 9999): ").strip()
            
            if ':' in host_input:
                host_ip, port = host_input.split(':')
                port = int(port)
            else:
                host_ip = host_input
                port = 9999
            
            print("=" * 40)
            chat.connect_to_host(host_ip, port)
            break
            
        elif choice == '3':
            chat.demo_hmac_verification()
            print("\nPress Enter to continue...")
            input()
            continue
            
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


