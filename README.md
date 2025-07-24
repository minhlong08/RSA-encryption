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
- ✅ Breaking RSA: factorising RSA key and chosen ciphertext attack
- ✅ Application of RSA: End-to-end encrypted chat

## 🛠️ Tech Stack

- Language: Python


## 📂 Files Overview
- rsa_simple.py: most simple implementation of RSA
- rsa.py: textbook implementation of RSA (no padding)
- rsa_pkcs.py: rsa with PKCS#1 v1.5 padding scheme
- rsa_oaep.py: rsa with OAEP padding scheme
- math_utils.py: helper math functions (prime generation, extended Euclidean algorithm, mod_inverse)
- breaking_rsa: algorithm to factor RSA keys
- bleichenbacher_attack.py: simple demo of bleichenbacher chosen ciphertext attack on RSA PKCS#1 v1.5
- app.py: flask backend for demo purposes
- chat.py: version 1 of end to end encrypted chat
- chatv2.py: version 2 of end to edn encrypted chat (has message authentication using HMAC)
- mitm_tamper.py: Man in the middle attack script
- rsa_demo.py: GUI demo for RSA (obsolete)

