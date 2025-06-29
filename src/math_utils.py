from typing import Tuple
import random

class MathUtils:
    @staticmethod
    def is_prime(n: int, k: int = 5) -> bool:
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