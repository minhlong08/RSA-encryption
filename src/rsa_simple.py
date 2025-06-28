import random
import math


d = None
n = None
e = None



def is_prime(number):
    """
    Function to check if a number is prime
    Input: integer number
    Output: True if is a prime number, false otherwise
    """
    if number < 2:
        return False
    if number in (2, 3):
        return True
    if number % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(number)) + 1, 2):
        if number % i == 0:
            return False
    return True


def generate_prime (min_value, max_value):
    """
    Function to generate a prime number (not that efficient)
    """
    prime = random.randint (min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime


def mod_inverse(e, phi):
    """
    Function to find d (private key)
    """
    for d in range (3, phi):
        if (d * e) % phi == 1:
            return d 
    raise ValueError ("Mod_inverse does not exist!")

def generate_keys():
    """Generate RSA key pair and store them in global variables."""
    global d, n, e
    while True:
        p = generate_prime(1000, 50000)
        q = generate_prime(1000, 50000)
        if p == q:
            continue
        n = p * q
        if n < 65536:
            continue  # ensure modulus is large enough for Unicode
        phi_n = (p - 1) * (q - 1)
        e = random.randint(3, phi_n - 1)
        while math.gcd(e, phi_n) != 1 or not is_prime(e):
            e = random.randint(3, phi_n - 1)
        d = mod_inverse(e, phi_n)
        break

def encrypt(message):
    """Encrypt a string message using the public key."""
    message_bytes = message.encode('utf-8')
    ciphertext = [pow(byte, e, n) for byte in message_bytes]
    return ciphertext

def decrypt(ciphertext):
    """Decrypt a list of integers using the private key."""
    decrypted_bytes = bytes([pow(byte, d, n) for byte in ciphertext])
    return decrypted_bytes.decode('utf-8')


if __name__ == "__main__":
    generate_keys()

    message = input("Enter you message to encrypt: ")
    print("Original Message:", message)

    cipher = encrypt(message)
    print("Encrypted:", cipher)

    plain = decrypt(cipher)
    print("Decrypted:", plain)
