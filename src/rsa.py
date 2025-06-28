import random
import math
from typing import Tuple, List

class RSA:
    def __init__(self, key_size: int = 1024):
        """
        Initialize RSA with specified key size in bits.
        For demonstration, we'll use smaller default keys.
        """
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
    
    def is_prime(self, n: int, k: int = 5) -> bool:
        """
        Miller-Rabin primality test.
        Returns True if n is probably prime, False if composite.
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Write n-1 as d * 2^r
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Perform k rounds of testing
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def generate_prime(self, bits: int) -> int:
        """Generate a random prime number with specified bit length."""
        while True:
            # Generate random odd number with specified bit length
            candidate = random.getrandbits(bits)
            candidate |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
            
            if self.is_prime(candidate):
                return candidate
    
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm.
        Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
        """
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def mod_inverse(self, a: int, m: int) -> int:
        """Calculate modular inverse of a modulo m."""
        gcd, x, _ = self.extended_gcd(a, m)
        
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        
        return (x % m + m) % m
    
    def generate_keypair(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Generate RSA public and private key pair.
        Returns ((e, n), (d, n)) where (e, n) is public key and (d, n) is private key.
        """
        # Generate two distinct prime numbers
        p = self.generate_prime(self.key_size // 2)
        q = self.generate_prime(self.key_size // 2)
        
        # Ensure p and q are different
        while p == q:
            q = self.generate_prime(self.key_size // 2)
        
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
        d = self.mod_inverse(e, phi_n)
        
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
    rsa = RSA(key_size=512)  # Use 2048 or higher for real applications
    
    print("Generating RSA key pair...")
    public_key, private_key = rsa.generate_keypair()
    
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
    string_message = "Hello, RSA Encryption! How are you"
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