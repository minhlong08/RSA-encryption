import math
from rsa import RSA
from math_utils import MathUtils
from typing import Tuple, List

class BREAKING_RSA:
    @staticmethod
    def trial_division(public_key: Tuple[int, int]) -> Tuple[int, int]:
        """
        Naive brute force approach: try to divide n by every prime number up to sqrt(n).
        Only work for very small n
        """
        e = public_key[0]
        n = public_key[1]
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                p = i
                q = n // i
                phi_n = (p-1)*(q-1)
                d = MathUtils.mod_inverse(e, phi_n)
                return (d,n)
        return (None, None)

    @staticmethod
    def fermat_factor(public_key: Tuple[int, int]) -> Tuple[int, int]:
        """
        Use Fermat's Factorization method
        Very fast if p and q are close even if n are large (even up to 2048 bits).
        """
        e = public_key[0]
        n = public_key[1]
        x = math.isqrt(n) + 1
        while True:
            y2 = x*x - n
            y = math.isqrt(y2)
            if y*y == y2:
                p = x - y
                q = x + y
                phi_n = (p-1)*(q-1)
                d = MathUtils.mod_inverse(e, phi_n)
                return (d,n)
            x += 1


# Example usage
if __name__ == "__main__":
    print("Very small RSA key (16 bits)")
    rsa = RSA(key_size=16)
    print("Generating RSA key pair...")
    public_key, _ = rsa.generate_keypair()
    print(f"Public Key (e, n): ({public_key[0]}, {public_key[1]})")

    print("Encrypting a secret message...")
    message = "This is a secret message"
    encrypted_blocks = rsa.encrypt_string(message)
    print(f"Encrypted blocks: {encrypted_blocks}")

    print(f"Breaking RSA...")
    print(f"e = {public_key[0]}")
    print(f"n = {public_key[1]}")
    private_key = BREAKING_RSA.trial_division(public_key)
    print(f"d = {private_key}")

    print("Decrypting the secret message...")
    decrypted_string = rsa.decrypt_string(encrypted_blocks, private_key)
    print(f"Decrypted string: '{decrypted_string}'")

