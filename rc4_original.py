def rc4_ksa(key):
    # Key Scheduling Algorithm
    key = [ord(c) for c in key]  # تحويل المفتاح لأرقام
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, length):
    # Pseudo-Random Generation Algorithm
    i = 0
    j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    return keystream

def rc4_encrypt(key, plaintext):
    S = rc4_ksa(key)
    keystream = rc4_prga(S, len(plaintext))
    ciphertext = []
    for i in range(len(plaintext)):
        ciphertext.append(chr(ord(plaintext[i]) ^ keystream[i]))
    return ''.join(ciphertext)

def rc4_decrypt(key, ciphertext):
    # نفس العملية (XOR)
    return rc4_encrypt(key, ciphertext)

# مثال استخدام
if __name__ == "__main__":
    key = "secret"
    plaintext = "Hello World"
    encrypted = rc4_encrypt(key, plaintext)
    decrypted = rc4_decrypt(key, encrypted)
    print("Plaintext:", plaintext)
    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
