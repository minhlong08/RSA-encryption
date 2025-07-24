"""
RSA-PKCS#1 v1.5 Implementation
=======================

This module implements RSA with PKCS#1 v1.5 padding. This is the simplest padding scheme for RSA.

"""

import secrets
from typing import Tuple, List
from rsa import RSA

class RSAWithPKCS1(RSA):
    """
    RSA implementation with PKCS#1 v1.5 padding support.
    """
    
    def __init__(self, key_size: int = 1024):
        super().__init__(key_size)
    
    def _pkcs1_v15_pad(self, data: bytes, target_length: int, block_type: int = 2) -> bytes:
        """
        Apply PKCS#1 v1.5 padding to data.
        
        Args:
            data: The data to pad
            target_length: Target length in bytes (should be size of key in bytes)
            block_type: 2 for encryption
        
        Returns:
            Padded data as bytes
        """
        if len(data) > target_length - 11:
            raise ValueError("Data too long for PKCS#1 v1.5 padding")
        
        # PKCS#1 v1.5 format: 0x00 || BT || PS || 0x00 || D
        # Where BT is block type which is 0x02 for encryption, PS is padding string, D is data
        
        padding_length = target_length - len(data) - 3
        
        # Encryption operation: padding string is random non-zero bytes
        padding_string = b''
        for _ in range(padding_length):
            # Generate random non-zero byte
            byte_val = secrets.randbits(8)
            while byte_val == 0:
                byte_val = secrets.randbits(8)
            padding_string += bytes([byte_val])

        
        # Construct padded message: 0x00 || BT || PS || 0x00 || D
        padded_data = b'\x00' + bytes([block_type]) + padding_string + b'\x00' + data
        
        return padded_data
    
    def _pkcs1_v15_unpad(self, padded_data: bytes, block_type: int = 2) -> bytes:
        """
        Remove PKCS#1 v1.5 padding from data.
        
        Args:
            padded_data: The padded data
            block_type: Expected block type (2 for encryption)
        
        Returns:
            Original data without padding
        """
        if len(padded_data) < 11:
            raise ValueError("Invalid padded data length")
        
        # Check first byte (should be 0x00)
        if padded_data[0] != 0x00:
            raise ValueError("Invalid PKCS#1 v1.5 padding: first byte not 0x00")
        
        # Check block type
        if padded_data[1] != block_type:
            raise ValueError(f"Invalid block type: expected {block_type}, got {padded_data[1]}")
        
        # Find the 0x00 separator after padding string
        separator_index = -1
        for i in range(2, len(padded_data)):
            if padded_data[i] == 0x00:
                separator_index = i
                break
        
        if separator_index == -1:
            raise ValueError("Invalid PKCS#1 v1.5 padding: no separator found")
        
        # Check minimum padding length (at least 8 bytes for block type 2)
        if block_type == 2 and separator_index < 10:
            raise ValueError("Invalid PKCS#1 v1.5 padding: insufficient padding length")
        
        # Extract original data
        original_data = padded_data[separator_index + 1:]
        
        return original_data
    
    def encrypt_with_padding(self, data: bytes, public_key: Tuple[int, int] = None) -> int:
        """
        Encrypt data using RSA with PKCS#1 v1.5 padding.
        
        Args:
            data: The data to encrypt (as bytes)
            public_key: Public key tuple (e, n)
        
        Returns:
            Encrypted integer
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available. Generate keys first.")
            public_key = self.public_key
        
        e, n = public_key
        
        # Calculate key length in bytes
        key_length = RSA.calculate_key_size_bytes(n)
        
        # Apply PKCS#1 v1.5 padding
        padded_data = self._pkcs1_v15_pad(data, key_length, block_type=2)
        
        # Convert padded data to integer
        message_int = int.from_bytes(padded_data, byteorder='big')

        return super().encrypt(message_int, public_key)
    
    def decrypt_with_padding(self, ciphertext: int, private_key: Tuple[int, int] = None) -> bytes:
        """
        Decrypt ciphertext using RSA with PKCS#1 v1.5 padding.
        
        Args:
            ciphertext: The encrypted integer
            private_key: Private key tuple (d, n)
        
        Returns:
            Original data as bytes
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("No private key available. Generate keys first.")
            private_key = self.private_key
        
        d, n = private_key
        
        # Decrypt using parent class method
        decrypted_int = super().decrypt(ciphertext, private_key)
        
        # Calculate key length in bytes
        key_length = RSA.calculate_key_size_bytes(n)
        
        # Convert integer back to bytes
        decrypted_bytes = decrypted_int.to_bytes(key_length, byteorder='big')
        
        # Remove PKCS#1 v1.5 padding
        original_data = self._pkcs1_v15_unpad(decrypted_bytes, block_type=2)
        
        return original_data
    
    def encrypt_string(self, message: str, public_key: Tuple[int, int] = None, use_padding: bool = True) -> List[int]:
        """
        Encrypt a string message by converting to bytes and encrypting each block.
        
        Args:
            message: The string to encrypt
            public_key: Public key tuple (e, n)
            use_padding: Whether to use PKCS#1 v1.5 padding (default: True)
        
        Returns:
            List of encrypted blocks
        """
        if public_key is None:
            public_key = self.public_key
        
        _, n = public_key
        
        message_bytes = message.encode('utf-8')
        encrypted_blocks = []
        
        if use_padding:
            # Calculate maximum data size per block (accounting for PKCS#1 v1.5 padding overhead)
            key_length = RSA.calculate_key_size_bytes(n)
            max_data_size = key_length - 11  # PKCS#1 v1.5 requires 11 bytes overhead
            
            for i in range(0, len(message_bytes), max_data_size):
                block = message_bytes[i:i + max_data_size]
                
                # encrypt
                encrypted_block = self.encrypt_with_padding(block, public_key)
                encrypted_blocks.append(encrypted_block)
        else:
            # Use parent class method (no padding)
            return super().encrypt_string(message, public_key)
        
        return encrypted_blocks
    
    def decrypt_string(self, encrypted_blocks: List[int], private_key: Tuple[int, int] = None, use_padding: bool = True) -> str:
        """
        Decrypt a list of encrypted blocks back to original string.
        
        Args:
            encrypted_blocks: List of encrypted blocks
            private_key: Private key tuple (d, n)
            use_padding: Whether to expect PKCS#1 v1.5 padding (default: True)
        
        Returns:
            Original string
        """
        if private_key is None:
            private_key = self.private_key
        
        if use_padding:
            decrypted_bytes = b''
            
            # Decrypt each block with padding removal
            for encrypted_block in encrypted_blocks:
                decrypted_block = self.decrypt_with_padding(encrypted_block, private_key)
                decrypted_bytes += decrypted_block
            
            return decrypted_bytes.decode('utf-8')
        else:
            # Use parent class method (no padding)
            return super().decrypt_string(encrypted_blocks, private_key)


# Example usage and demonstration
if __name__ == "__main__":
    import time
    
    print("=== RSA with PKCS#1 v1.5 Padding Class ===")
    # Create RSA with padding instance
    padded_rsa = RSAWithPKCS1(key_size=1024)
    rsa = RSA(key_size=1024)
    
    starttime = time.time()
    print("Generating RSA key pair...")
    public_key, private_key = padded_rsa.generate_keypair()
    endtime = time.time()

    runtime = endtime - starttime
    print(f"Key generation (keysize = {padded_rsa.get_key_size()}) took {runtime:.6f} seconds")
    
    print(f"Public Key (e, n): ({public_key[0]}, {public_key[1]})")
    print(f"Private Key (d, n): ({private_key[0]}, {private_key[1]})")
    print()
    
    # Test with PKCS#1 v1.5 padding
    test_data = b"Hello, RSA with PKCS#1 v1.5 padding!"
    print(f"Original data: {test_data}")
    
    encrypted_padded = padded_rsa.encrypt_with_padding(test_data)
    print(f"Encrypted (with padding): {encrypted_padded}")
    
    decrypted_padded = padded_rsa.decrypt_with_padding(encrypted_padded)
    print(f"Decrypted (with padding): {decrypted_padded}")
    print(f"Padding decryption successful: {test_data == decrypted_padded}")
    print()
    
    # Test string encryption with padding
    string_message = "This is a test message for encryption with padding!"
    print(f"Original message: '{string_message}'")
    
    # With padding (default)
    padded_encrypted = padded_rsa.encrypt_string(string_message, use_padding=True)
    padded_decrypted = padded_rsa.decrypt_string(padded_encrypted, use_padding=True)
    print(f"Padded RSA - Encrypted blocks: {len(padded_encrypted)} blocks")
    print(f"Padded RSA - Decrypted: '{padded_decrypted}'")
    print(f"Padded RSA - Success: {string_message == padded_decrypted}")
    print()
    
    # Without padding (backwards compatibility)
    no_padding_encrypted = padded_rsa.encrypt_string(string_message, use_padding=False)
    no_padding_decrypted = padded_rsa.decrypt_string(no_padding_encrypted, use_padding=False)
    print(f"No padding mode - Encrypted blocks: {len(no_padding_encrypted)} blocks")
    print(f"No padding mode - Decrypted: '{no_padding_decrypted}'")
    print(f"No padding mode - Success: {string_message == no_padding_decrypted}")
    print()
    
    # Show security difference
    print("=== Security Demonstration ===")
    same_message = b"Same message"
    
    # Without padding - deterministic
    no_pad_enc1 = padded_rsa.encrypt(int.from_bytes(same_message, 'big'))
    no_pad_enc2 = padded_rsa.encrypt(int.from_bytes(same_message, 'big'))
    print(f"No padding - Same message encrypted twice gives same result: {no_pad_enc1 == no_pad_enc2}")
    
    # With padding - randomized
    padded_enc1 = padded_rsa.encrypt_with_padding(same_message)
    padded_enc2 = padded_rsa.encrypt_with_padding(same_message)
    print(f"With padding - Same message encrypted twice gives same result: {padded_enc1 == padded_enc2}")
    
    # Both should decrypt to same original message
    dec1 = padded_rsa.decrypt_with_padding(padded_enc1)
    dec2 = padded_rsa.decrypt_with_padding(padded_enc2)
    print(f"Both padded encryptions decrypt to same original: {dec1 == dec2 == same_message}")