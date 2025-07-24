"""
RSA Implementation
=======================

This module implements textbook RSA algorithm (no padding scheme included).

"""
import math
import time
from math_utils import MathUtils
from typing import Tuple, List

class RSA:
    def __init__(self, key_size: int = 1024):
        """
        Initialize RSA with specified key size in bits.
        Default jey size to be 1024
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    
    def get_key_size(self) -> int:
        """
        Return the RSA key size in bits.
        """
        return self.key_size
    
    @staticmethod
    def calculate_key_size_bytes(n: int) -> int:
        """
        Calculate the key size in bytes
        """
        return (n.bit_length() + 7) // 8
    
    @staticmethod
    def calculate_key_size_bits(n: int) -> int:
        """
        Calculate the key size in bits
        """
        return n.bit_length()
    
    
    def generate_keypair(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generate RSA public and private key pair.
        Returns ((e, n), (d, n)) where (e, n) is public key and (d, n) is private key.
        """
        # Generate two distinct prime numbers
        p = MathUtils.generate_prime(self.key_size // 2)
        q = MathUtils.generate_prime(self.key_size // 2)
        
        # Ensure p and q are different
        while p == q:
            q = MathUtils.generate_prime(self.key_size // 2)
        
        # Calculate n = p * q
        n = p * q
        
        # Calculate Euler's totient function φ(n) = (p-1)(q-1)
        phi_n = (p - 1) * (q - 1)
        
        # Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        # Common choice is 65537 (2^16 + 1)
        e = 65537
        while math.gcd(e, phi_n) != 1:  
            e += 2
        
        # Calculate d, the modular inverse of e modulo φ(n)
        d = MathUtils.mod_inverse(e, phi_n)
        
        # Store keys
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        return self.public_key, self.private_key
    
    def encrypt(self, message: int, public_key: Tuple[int, int] = None) -> int:
        """
        Encrypt a message using RSA public key.
        Message must be an integer less than n.
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available. Generate keys first.")
            public_key = self.public_key
        
        e, n = public_key
        
        if message >= n:
            raise ValueError("Message too large for key size")
        
        return pow(message, e, n)
    
    def decrypt(self, ciphertext: int, private_key: Tuple[int, int] = None) -> int:
        """
        Decrypt a ciphertext using RSA private key.
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("No private key available. Generate keys first.")
            private_key = self.private_key
        
        d, n = private_key
        return pow(ciphertext, d, n)
    
    def encrypt_string(self, message: str, public_key: Tuple[int, int] = None) -> List[int]:
        """
        Encrypt a string message by converting to bytes and encrypting each block.
        """
        if public_key is None:
            public_key = self.public_key
        
        _, n = public_key
        
        # Calculate maximum block size (in bytes) that can fit in n
        max_block_size = (n.bit_length() - 1) // 8
        
        message_bytes = message.encode('utf-8')
        encrypted_blocks = []
        
        # Split message into blocks and encrypt each
        for i in range(0, len(message_bytes), max_block_size):
            block = message_bytes[i:i + max_block_size]
            
            # Convert block to integer
            block_int = int.from_bytes(block, byteorder='big')
            
            # Encrypt block
            encrypted_block = self.encrypt(block_int, public_key)
            encrypted_blocks.append(encrypted_block)
        
        return encrypted_blocks
    
    def decrypt_string(self, encrypted_blocks: List[int], private_key: Tuple[int, int] = None) -> str:
        """
        Decrypt a list of encrypted blocks back to original string.
        """
        if private_key is None:
            private_key = self.private_key
        
        _, n = private_key
        max_block_size = (n.bit_length() - 1) // 8
        
        decrypted_bytes = b''
        
        # Decrypt each block
        for encrypted_block in encrypted_blocks:
            decrypted_int = self.decrypt(encrypted_block, private_key)
            
            # Convert back to bytes
            byte_length = (decrypted_int.bit_length() + 7) // 8
            decrypted_block = decrypted_int.to_bytes(byte_length, byteorder='big')
            decrypted_bytes += decrypted_block
        
        return decrypted_bytes.decode('utf-8')


# Example usage and demonstration
if __name__ == "__main__":
    # Create RSA instance with smaller key size for faster demonstration
    rsa = RSA(key_size=1024)  # Use 2048 or higher for real applications
    
    startime = time.time()
    print("Generating RSA key pair...")
    public_key, private_key = rsa.generate_keypair()
    endtime = time.time()

    runtime = endtime - startime
    print(f"Key generation (keysize = {rsa.get_key_size()}) took {runtime:.6f} seconds")
    
    print(f"Public Key (e, n): ({public_key[0]}, {public_key[1]})")
    print(f"Private Key (d, n): ({private_key[0]}, {private_key[1]})")
    print()
    
    # Test with integer message
    message = 12345
    print(f"Original message (integer): {message}")
    
    encrypted = rsa.encrypt(message)
    print(f"Encrypted: {encrypted}")
    
    decrypted = rsa.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    print(f"Decryption successful: {message == decrypted}")
    print()
    
    # Test with string message
    string_message = input("Enter the message you want to encrypt: ")
    print(f"Original message (string): '{string_message}'")
    
    encrypted_blocks = rsa.encrypt_string(string_message)
    print(f"Encrypted blocks: {encrypted_blocks}")
    
    decrypted_string = rsa.decrypt_string(encrypted_blocks)
    print(f"Decrypted string: '{decrypted_string}'")
    print(f"String decryption successful: {string_message == decrypted_string}")
    
    # Demonstrate that you can encrypt with public key and decrypt with private key
    print("\nDemonstrating public/private key separation:")
    message2 = 9876
    encrypted_with_public = rsa.encrypt(message2, public_key)
    decrypted_with_private = rsa.decrypt(encrypted_with_public, private_key)
    print(f"Message: {message2}")
    print(f"Encrypted with public key: {encrypted_with_public}")
    print(f"Decrypted with private key: {decrypted_with_private}")
    print(f"Cross-key operation successful: {message2 == decrypted_with_private}")