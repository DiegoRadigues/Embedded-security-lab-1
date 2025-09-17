#!/usr/bin/env python3
import string

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    alphabet = string.ascii_uppercase
    plaintext = []
    key = key.upper()
    key_index = 0

    for char in ciphertext:
        if char.upper() in alphabet:
            ci = alphabet.index(char.upper())
            ki = alphabet.index(key[key_index % len(key)])
            pi = (ci - ki) % 26
            new_char = alphabet[pi]
            if char.islower():
                new_char = new_char.lower()
            plaintext.append(new_char)
            key_index += 1
        else:
            plaintext.append(char)
    return "".join(plaintext)

def main():
    print("=== Déchiffrement Vigenère ===")
    ciphertext = input("Entrez le message chiffré : ").strip()
    key = input("Entrez la clé : ").strip()
    if not key:
        print("[!] Clé vide, arrêt.")
        return

    result = vigenere_decrypt(ciphertext, key)
    print("\n=== Résultat ===")
    print(result)

if __name__ == "__main__":
    main()
