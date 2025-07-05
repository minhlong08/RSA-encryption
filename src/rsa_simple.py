import random
import math


class RSA_SIMPLE:
    def __init__(self):
        self.d = None
        self.n = None
        self.e = None

    def is_prime(self, number):
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

    def generate_prime(self, min_value, max_value):
        prime = random.randint(min_value, max_value)
        while not self.is_prime(prime):
            prime = random.randint(min_value, max_value)
        return prime

    def mod_inverse(self, e, phi):
        for d in range(3, phi):
            if (d * e) % phi == 1:
                return d
        raise ValueError("Mod_inverse does not exist!")

    def generate_keys(self):
        while True:
            p = self.generate_prime(1000, 50000)
            q = self.generate_prime(1000, 50000)
            if p == q:
                continue
            self.n = p * q
            if self.n < 65536:
                continue
            phi_n = (p - 1) * (q - 1)
            self.e = random.randint(3, phi_n - 1)
            while math.gcd(self.e, phi_n) != 1 or not self.is_prime(self.e):
                self.e = random.randint(3, phi_n - 1)
            self.d = self.mod_inverse(self.e, phi_n)
            break

    def get_public_key(self):
        return (self.e, self.n)

    def get_private_key(self):
        return (self.d, self.n)

    def encrypt(self, message, public_key=None):
        if public_key is not None:
            e, n = public_key
        else:
            e, n = self.e, self.n

        message_bytes = message.encode('utf-8')
        ciphertext = [pow(byte, e, n) for byte in message_bytes]
        return ciphertext

    def decrypt(self, ciphertext, private_key=None):
        if private_key is not None:
            d, n = private_key
        else:
            d, n = self.d, self.n

        decrypted_bytes = bytes([pow(byte, d, n) for byte in ciphertext])
        return decrypted_bytes.decode('utf-8')


if __name__ == "__main__":
    rsa = RSA_SIMPLE()
    rsa.generate_keys()

    message = input("Enter your message to encrypt: ")
    print("Original Message:", message)

    cipher = rsa.encrypt(message)
    print("Encrypted:", cipher)

    plain = rsa.decrypt(cipher)
    print("Decrypted:", plain)
