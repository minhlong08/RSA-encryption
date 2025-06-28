# RSA from Scratch 🔐

This repository contains my personal implementation of the RSA encryption algorithm, written from scratch. The project is intended for educational purposes to better understand how RSA works under the hood — from key generation to encryption and decryption.

## 📘 What is RSA?

- RSA (Rivest–Shamir–Adleman) is one of the first public-key cryptosystems and is widely used for secure data transmission.
- Created in 1977 by: Ron Rivest, Adi Shamir, Leonard Adleman
- The most common Asymmetric Encryption algorithm 
- It relies on the mathematical difficulty of factoring large prime numbers.

## 🚀 Features

- ✅ Generate RSA key pairs (public and private)
- ✅ Encrypt messages using the public key
- ✅ Decrypt messages using the private key
- ✅ Support for arbitrary-length messages (split into blocks)
- ✅ All logic implemented manually — no use of external cryptography libraries

## 🛠️ Tech Stack

- Language: Python


## 📂 Files Overview



## 🔢 How It Works (Simplified)

1. **Key Generation**
   - Choose two large prime numbers `p` and `q`
   - Compute `n = p * q`
   - Compute Euler's totient `φ(n) = (p-1)*(q-1)`
   - Choose an encryption exponent `e` requirement:
   + `e` must be prime
   + `1 < e < φ(n)`
   + `gcd(e, φ(n)) = 1`
   - Compute the decryption exponent `d` such that `d ≡ e⁻¹ mod φ(n)`
   - Public key: `(e, n)`, Private key: `(d, n)`

2. **Encryption**
   - Convert message `M` to integer blocks `m`
   - Compute ciphertext `c = m^e mod n`

3. **Decryption**
   - Compute plaintext `m = c^d mod n`
   - Convert integer back to text


