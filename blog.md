1. Week 3
- Wrote a very simple implementation of RSA using python
- This implementation is still highly ineffective, especially in algorithm of generating key: Algorithm for checking prime number, calculating the mod_inverse is slow
- Have not taken into consideration of key length (this play a big role in the maximum size of block we can encrypt at a time)
- Exploitation: ...

2. Week 4
- Improve the algorithm (checking prime number, calculating modular inverse)
- Learn about the important of key length, implementing key length into the algorithm
- Learn about drawback of RSA which is deterministic (the same message always produces the same ciphertext which make attacker can easily attack). Demo of exploitation: ...
- Learn about padding scheme (PKCS#1 v1.5)
- Going to implement this padding scheme into the algorithm.