"""
An demo attack script of a chosen ciphertext attack on RSA-PKCS#1 v1.5
This attack is called the Bleichenbacher attack
"""
from rsa_pkcs import RSAWithPKCS1
import time


def ceildiv(a, b):
    return -(-a // b)

def floordiv(a, b):
    return a // b

def is_conformant(ciphertext: int, rsa: RSAWithPKCS1) -> bool:
    """
    This is our padding oracle.
    Return true if the decryption of the ciphertext has the correct structure (start with 0x0002)
    False otherwise
    """
    try:
        rsa.decrypt_with_padding(ciphertext)
        return True
    except ValueError:
        return False

def bleichenbacher_attack(ciphertext: int, rsa: RSAWithPKCS1):
    e, n = rsa.public_key
    k = (n.bit_length() + 7) // 8  # key size in bytes
    B = 2 ** (8 * (k - 2))         # 2B is minimum PKCS-conformant plaintext
    
    print(f"[i] Key size: {k} bytes")
    print(f"[i] B = 2^{8 * (k - 2)} = {B}")

    # Step 1: Blinding (we skip if ciphertext is already conformant)
    if not is_conformant(ciphertext, rsa):
        raise ValueError("Ciphertext must be PKCS conformant for this simplified attack")
    print("[+] Ciphertext is PKCS#1 conformant")

    # Step 2: Initial s1 search
    s = ceildiv(n, 3 * B)
    print(f"[i] Starting s search from: {s}")
    
    oracle_queries = 0
    while True:
        c0 = (ciphertext * pow(s, e, n)) % n
        oracle_queries += 1
        if is_conformant(c0, rsa):
            break
        s += 1
        
        # # Add some progress reporting for large searches
        # if oracle_queries % 1000 == 0:
        #     print(f"[i] Searched {oracle_queries} values, current s: {s}")
    
    print(f"[+] Found initial conformant s: {s} (after {oracle_queries} queries)")

    # Step 3: Set initial interval
    M = [(2 * B, 3 * B - 1)]  # Only one interval initially
    print(f"[i] Initial interval: [{hex(M[0][0])}, {hex(M[0][1])}]")
    print(f"[i] Interval size: {M[0][1] - M[0][0] + 1}")

    iteration = 0
    # Step 4: Narrowing
    while True:
        iteration += 1
        print(f"\n[i] === Iteration {iteration} ===")
        
        # Step 4.a: If multiple intervals, continue linear search
        if len(M) >= 2:
            s += 1
            while True:
                c_test = (ciphertext * pow(s, e, n)) % n
                oracle_queries += 1
                if is_conformant(c_test, rsa):
                    break
                s += 1
        else:
            # Step 4.b: Single interval case
            a, b = M[0]
            r = ceildiv(2 * (b * s - 2 * B), n)
            found = False
            search_count = 0
            
            while not found:
                lower = ceildiv(2 * B + r * n, b)
                upper = floordiv(3 * B + r * n, a)
                
                # print(f"[i] Searching r={r}, s range: [{lower}, {upper}]")
                
                for s_try in range(lower, upper + 1):
                    c_test = (ciphertext * pow(s_try, e, n)) % n
                    oracle_queries += 1
                    search_count += 1
                    
                    if is_conformant(c_test, rsa):
                        s = s_try
                        found = True
                        print(f"[+] Found conformant s: {s} (r={r})")
                        break
                
                if not found:
                    r += 1
                    # Safety check to prevent infinite loops
                    if search_count > 10000000:
                        print("[!] Search taking too long")
                        return None

        # Step 4.c: Update intervals
        new_intervals = []
        for a, b in M:
            r_min = ceildiv(a * s - 3 * B + 1, n)
            r_max = floordiv(b * s - 2 * B, n)
            for r in range(r_min, r_max + 1):
                new_a = max(a, ceildiv(2 * B + r * n, s))
                new_b = min(b, floordiv(3 * B - 1 + r * n, s))
                if new_a <= new_b:
                    new_intervals.append((new_a, new_b))
        
        M = new_intervals
        print(f"[i] Updated intervals: {len(M)} intervals")
        for i, (a, b) in enumerate(M):
            print(f"    Interval {i}: [{hex(a)}, {hex(b)}] (size: {b-a+1})")
        
        # Safety check
        if len(M) == 0:
            print("[!] No valid intervals found - attack failed")
            return None

        # Step 4.d: Check if solution found
        if len(M) == 1:
            a, b = M[0]
            if a == b:
                m = a
                print(f"\n[+] Found exact plaintext integer: {m}")
                print(f"[+] Total oracle queries: {oracle_queries}")
                
                try:
                    m_bytes = m.to_bytes(k, 'big')
                    unpadded = rsa._pkcs1_v15_unpad(m_bytes)
                    recovered_str = unpadded.decode('utf-8')  # Convert bytes to string
                    print(f"[+] Recovered message: '{recovered_str}'")
                    return recovered_str
                except Exception as e:
                    print(f"[!] Error recovering message: {e}")
                    return None
            
def main():
    # Demo with 256 bit key
    rsa = RSAWithPKCS1(key_size=256)
    rsa.generate_keypair()
    
    plaintext = input("Enter the message you want to encrypt): ")
    print(f"[*] Plaintext: '{plaintext}'")

    ciphertext = rsa.encrypt_string(plaintext)
    print(f"[*] Ciphertext blocks: {len(ciphertext)}")

    if len(ciphertext) != 1:
        print(f"[!] Warning: Message was split into {len(ciphertext)} blocks.")
        print("[!] This demo only works with single-block messages.")
        print("[!] Try a shorter message.")
        return
    
    print(f"[*] Single ciphertext: {ciphertext[0]}")
    
    starttime = time.time()
    recovered = bleichenbacher_attack(ciphertext[0], rsa)
    endtime = time.time()
    runtime = endtime - starttime

    if recovered is not None:
        print(f"\n[✓] Attack success: {recovered == plaintext}")
        print(f"[*] Original:  '{plaintext}'")
        print(f"[*] Recovered: '{recovered}'")
        print(f"Took {runtime:.6f} seconds ({runtime/60:.2f} minutes) to break key size of {rsa.get_key_size()} bits")
    else:
        print("[✗] Attack failed")

if __name__ == "__main__":
    main()

