from typing import Tuple
import random

SMALL_PRIMES = [
     2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
     61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
     131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
     197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
     271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
     353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431,
     433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
     509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
     601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673,
     677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761,
     769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857,
     859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
     953, 967, 971, 977, 983, 991, 997
]


class MathUtils:
    @staticmethod
    def is_prime(n: int, k: int = 100) -> bool:
        """
        Miller-Rabin primality test.
        Returns True if n is probably prime, False if composite.
        """

        # Filtering out obvious small and non-prime number
        if n < 2:
            return False
        
        for p in SMALL_PRIMES:
            if n == p:
                return True
            if n % p == 0:
                return False
        
        # Start the Miller-Rabin test
        # Write n-1 = d * 2^r
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
    
    @staticmethod
    def generate_prime(bits: int) -> int:
        """Generate a random prime number with specified bit length."""
        while True:
            # Generate random odd number with specified bit length
            candidate = random.getrandbits(bits)
            candidate |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
            
            if MathUtils.is_prime(candidate):
                return candidate
    
    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm.
        Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
        """
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = MathUtils.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """Calculate modular inverse of a modulo m."""
        gcd, x, _ = MathUtils.extended_gcd(a, m)
        
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        
        return (x % m + m) % m