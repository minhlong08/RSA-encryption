"""
RSA-OAEP Implementation
=======================

This module implements RSA with OAEP (Optimal Asymmetric Encryption Padding)

"""

import math
import time
import hashlib
import os
from math_utils import MathUtils
from typing import Tuple, List, Optional
from rsa import RSA

class RSA_OAEP(RSA):
    def __init__(self, key_size: int = 2048, hash_func=hashlib.sha256):
        """
        Initialize RSA-OAEP with specified key size and hash function.
        
        Args:
            key_size (int): RSA key size in bits (minimum 2048 recommended)
            hash_func: Hash function to use (default: SHA-256)
        """
        super().__init__(key_size)
        self.hash_func = hash_func
        self.hash_length = hash_func().digest_size
    
    def _mgf1(self, seed: bytes, length: int) -> bytes:
        """
        MGF1 (Mask Generation Function) based on hash function.
        
        MGF1 is used in OAEP padding scheme to generate masks that randomize
        the plaintext structure, providing semantic security.
        
        Args:
            seed (bytes): Seed from which mask is generated
            length (int): Intended length in bytes of the mask
            
        Returns:
            bytes: An octet string of length 'length'
            
        Raises:
            ValueError: If mask length is too long
        """
        if length >= (1 << 32) * self.hash_length:
            raise ValueError("Mask too long")
        
        T = b''
        counter = 0
        
        while len(T) < length:
            C = counter.to_bytes(4, byteorder='big')
            T += self.hash_func(seed + C).digest()
            counter += 1
        
        return T[:length]
    
    def _oaep_encode(self, message: bytes, key_size:int, label: bytes = b'') -> bytes:
        """
        OAEP encoding of a message.
        
        The OAEP encoding process:
        1. Hash the label
        2. Create padding string
        3. Concatenate lHash, PS, 0x01, and message to form DB
        4. Generate random seed
        5. Generate masks using MGF1
        6. Apply masks to create encoded message
        
        Args:
            message (bytes): Message to be encoded
            key_size (bytes): key size
            label (bytes): Optional label to be associated with message
            
        Returns:
            bytes: OAEP encoded message
            
        Raises:
            ValueError: If message is too long for the key size
        """

        k = key_size
        m_len = len(message)
        
        # Check if message is too long
        if m_len > k - 2 * self.hash_length - 2:
            raise ValueError(f"Message too long for OAEP encoding. "
                           f"Maximum message length: {k - 2 * self.hash_length - 2} bytes")
        
        # Generate label hash
        l_hash = self.hash_func(label).digest()
        
        # Generate padding string PS of zeros
        ps_length = k - m_len - 2 * self.hash_length - 2
        ps = b'\x00' * ps_length
        
        # Concatenate lHash, PS, 0x01, and message to form DB
        db = l_hash + ps + b'\x01' + message
        
        # Generate random seed
        seed = os.urandom(self.hash_length)
        
        # Generate masks
        db_mask = self._mgf1(seed, k - self.hash_length - 1)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        
        seed_mask = self._mgf1(masked_db, self.hash_length)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        
        # Construct encoded message: 0x00 || maskedSeed || maskedDB
        em = b'\x00' + masked_seed + masked_db
        
        return em
    
    def _oaep_decode(self, encoded_message: bytes, key_size: int, label: bytes = b'') -> bytes:
        """
        OAEP decoding of an encoded message.
        
        The OAEP decoding process (reverse of encoding):
        1. Separate the encoded message into components
        2. Generate masks using MGF1
        3. Recover the seed and DB
        4. Verify label hash
        5. Find separator and extract message
        
        Args:
            encoded_message (bytes): OAEP encoded message
            key_size (bytes): key size
            label (bytes): Optional label that was associated with message
            
        Returns:
            bytes: Original message
            
        Raises:
            ValueError: If decoding fails (invalid format, wrong label, etc.)
        """
        k = key_size
        
        if len(encoded_message) != k:
            raise ValueError("Decoding error: invalid encoded message length")
        
        # Separate the encoded message
        if encoded_message[0] != 0:
            raise ValueError("Decoding error: first byte should be 0x00")
        
        masked_seed = encoded_message[1:self.hash_length + 1]
        masked_db = encoded_message[self.hash_length + 1:]
        
        # Generate seed mask and recover seed
        seed_mask = self._mgf1(masked_db, self.hash_length)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
        
        # Generate db mask and recover db
        db_mask = self._mgf1(seed, k - self.hash_length - 1)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
        
        # Verify label hash
        expected_l_hash = self.hash_func(label).digest()
        actual_l_hash = db[:self.hash_length]
        
        if actual_l_hash != expected_l_hash:
            raise ValueError("Decoding error: label hash mismatch")
        
        # Find the 0x01 separator
        i = self.hash_length
        while i < len(db) and db[i] == 0:
            i += 1
        
        if i == len(db) or db[i] != 1:
            raise ValueError("Decoding error: separator 0x01 not found")
        
        # Return the message
        return db[i + 1:]
    
    def encrypt_bytes(self, message: bytes, public_key: Tuple[int, int] = None, 
                     label: bytes = b'') -> int:
        """
        Encrypt bytes using RSA-OAEP.
        
        Args:
            message (bytes): Message bytes to encrypt
            public_key (Tuple[int, int]): RSA public key (e, n)
            label (bytes): Optional label for OAEP
            
        Returns:
            int: Encrypted integer
            
        Raises:
            ValueError: If no public key available or message too long
        """
        if public_key is None:
            if self.public_key is None:
                raise ValueError("No public key available. Generate keys first.")
            public_key = self.public_key
        
        e,n = public_key

        # key size in bytes
        key_size = RSA.calculate_key_size_bytes(n)
        # Apply OAEP encoding
        encoded_message = self._oaep_encode(message, key_size, label)
        
        # Convert to integer
        message_int = int.from_bytes(encoded_message, byteorder='big')
        
        return super().encrypt(message_int, public_key)
    
    def decrypt_bytes(self, ciphertext: int, private_key: Tuple[int, int] = None, 
                     label: bytes = b'') -> bytes:
        """
        Decrypt ciphertext using RSA-OAEP.
        
        Args:
            ciphertext (int): Encrypted integer
            private_key (Tuple[int, int]): RSA private key (d, n)
            label (bytes): Optional label for OAEP (must match encryption label)
            
        Returns:
            bytes: Decrypted message bytes
            
        Raises:
            ValueError: If no private key available or decryption fails
        """
        if private_key is None:
            if self.private_key is None:
                raise ValueError("No private key available. Generate keys first.")
            private_key = self.private_key
        
        d, n = private_key

        # Decrypt using base RSA
        decrypted_int = super().decrypt(ciphertext, private_key)
        

        # Convert key_size to bytes
        key_size = RSA.calculate_key_size_bytes(n)

        try:
            encoded_message = decrypted_int.to_bytes(key_size, byteorder='big')
        except OverflowError:
            raise ValueError("Decryption error: invalid ciphertext")
        
        # Apply OAEP decoding
        return self._oaep_decode(encoded_message, key_size=key_size, label= label)
    
    def encrypt_string(self, message: str, public_key: Tuple[int, int] = None, 
                      label: bytes = b'') -> List[int]:
        """
        Encrypt a string message using RSA-OAEP.
        
        For messages longer than the maximum block size, the message is
        automatically split into multiple blocks and each block is encrypted
        separately.
        
        Args:
            message (str): String message to encrypt
            public_key (Tuple[int, int]): RSA public key (e, n)
            label (bytes): Optional label for OAEP
            
        Returns:
            List[int]: List of encrypted integers (one per block)
        """
        if public_key is None:
            public_key = self.public_key
        
        message_bytes = message.encode('utf-8')
        
        e, n = public_key
        # Calculate maximum message size per block for OAEP
        k = (n.bit_length() - 1) // 8
        max_message_size = k - 2 * self.hash_length - 2
        
        encrypted_blocks = []
        
        # Split message into blocks and encrypt each
        for i in range(0, len(message_bytes), max_message_size):
            block = message_bytes[i:i + max_message_size]
            encrypted_block = self.encrypt_bytes(block, public_key, label)
            encrypted_blocks.append(encrypted_block)
        
        return encrypted_blocks
    
    def decrypt_string(self, encrypted_blocks: List[int], 
                      private_key: Tuple[int, int] = None, 
                      label: bytes = b'') -> str:
        """
        Decrypt a list of encrypted blocks back to original string using RSA-OAEP.
        
        Args:
            encrypted_blocks (List[int]): List of encrypted integers
            private_key (Tuple[int, int]): RSA private key (d, n)
            label (bytes): Optional label for OAEP (must match encryption label)
            
        Returns:
            str: Decrypted string
        """
        if private_key is None:
            private_key = self.private_key
        
        decrypted_bytes = b''
        
        # Decrypt each block
        for encrypted_block in encrypted_blocks:
            block_bytes = self.decrypt_bytes(encrypted_block, private_key, label)
            decrypted_bytes += block_bytes
        
        return decrypted_bytes.decode('utf-8')
    
    def get_max_message_size(self) -> int:
        """
        Get the maximum message size in bytes that can be encrypted in a single block.
        
        Returns:
            int: Maximum message size in bytes
        """
        k = self.key_size // 8
        return k - 2 * self.hash_length - 2


def main():
    """
    Demonstration of RSA-OAEP functionality.
    """
    print("=== RSA-OAEP Demonstration ===")
    print()
    
    # Create RSA-OAEP instance
    rsa_oaep = RSA_OAEP(key_size=2048)
    
    print(f"Maximum message size per block: {rsa_oaep.get_max_message_size()} bytes")
    print()
    
    start_time = time.time()
    print("Generating RSA key pair...")
    public_key, private_key = rsa_oaep.generate_keypair()
    end_time = time.time()
    
    runtime = end_time - start_time
    print(f"Key generation (keysize = {rsa_oaep.get_key_size()}) took {runtime:.6f} seconds")
    print()
    
    # Test with string message
    test_message = "Hello, RSA-OAEP! This is a secure message that demonstrates probabilistic encryption."
    print(f"Original message: '{test_message}'")
    print(f"Message length: {len(test_message)} characters")
    print()
    
    # Test encryption/decryption
    try:
        print("Encrypting message...")
        encrypted_blocks = rsa_oaep.encrypt_string(test_message)
        print(f"Number of encrypted blocks: {len(encrypted_blocks)}")
        print(f"First block (truncated): {str(encrypted_blocks[0])[:50]}...")
        
        print("Decrypting message...")
        decrypted_message = rsa_oaep.decrypt_string(encrypted_blocks)
        print(f"Decrypted message: '{decrypted_message}'")
        print(f"Encryption/Decryption successful: {test_message == decrypted_message}")
        
    except Exception as e:
        print(f"Error during encryption/decryption: {e}")
    
    print()
    
    # Test with label
    print("=== Testing with Label ===")
    label = b"secure-communication"
    try:
        encrypted_with_label = rsa_oaep.encrypt_string(test_message, label=label)
        decrypted_with_label = rsa_oaep.decrypt_string(encrypted_with_label, label=label)
        print(f"With label encryption/decryption successful: {test_message == decrypted_with_label}")
        
        # Try to decrypt with wrong label (should fail)
        try:
            wrong_label_decrypt = rsa_oaep.decrypt_string(encrypted_with_label, label=b"wrong-label")
            print("ERROR: Decryption with wrong label should have failed!")
        except ValueError as e:
            print(f"Correctly failed with wrong label: {str(e)[:60]}...")
            
    except Exception as e:
        print(f"Error during label test: {e}")
    
    print()
    
    # Demonstrate semantic security (probabilistic encryption)
    print("=== Demonstrating Semantic Security ===")
    short_message = "Test message"
    
    print(f"Testing message: '{short_message}'")
    print("OAEP encrypts the same plaintext to different ciphertexts:")
    
    try:
        oaep_enc1 = rsa_oaep.encrypt_string(short_message)
        oaep_enc2 = rsa_oaep.encrypt_string(short_message)
        print(f"Encryption 1 (first block): {oaep_enc1[0]}")
        print(f"Encryption 2 (first block): {oaep_enc2[0]}")
        print(f"Same ciphertext (should be false): {oaep_enc1 == oaep_enc2}")
        
        # Verify both decrypt correctly
        dec1 = rsa_oaep.decrypt_string(oaep_enc1)
        dec2 = rsa_oaep.decrypt_string(oaep_enc2)
        print(f"Both decrypt to original: {dec1 == short_message and dec2 == short_message}")
        
    except Exception as e:
        print(f"Error: {e}")
    
    print()
    print("=== Demo Complete ===")


if __name__ == "__main__":
    main()