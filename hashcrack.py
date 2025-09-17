# hashcrack.py
import hashlib
import os

# Dictionnaire pour détecter l'algorithme selon la longueur du hash
ALGOS_BY_LEN = {
    32: ("MD5", hashlib.md5),
    40: ("SHA1", hashlib.sha1),
    64: ("SHA256", hashlib.sha256)
}

# Chemin fixe vers ta wordlist
WORDLIST_PATH = r"C:\Users\diego\Documents\5MEO\Embedded security\Lab1\rockyou.txt"

def crack_hash(hash_value, wordlist_path):
    algo_info = ALGOS_BY_LEN.get(len(hash_value))
    if not algo_info:
        print(f"[!] Hash inconnu (longueur {len(hash_value)})")
        return None, None

    algo_name, algo_func = algo_info
    print(f"[i] Détection automatique → {algo_name}")

    try:
        with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if algo_func(word.encode()).hexdigest() == hash_value.lower():
                    return algo_name, word
    except FileNotFoundError:
        print(f"[!] Wordlist introuvable : {wordlist_path}")
        return None, None

    return algo_name, None

def main():
    print("=== Crack de hash automatique ===")
    print(f"[i] Utilisation de la wordlist : {WORDLIST_PATH}")

    while True:
        hash_value = input("\nEntrez le hash (ou 'exit' pour quitter) : ").strip()
        if not hash_value or hash_value.lower() == "exit":
            print("Fin du programme. 👋")
            break

        algo, pwd = crack_hash(hash_value, WORDLIST_PATH)
        if pwd:
            print(f"[✔] Mot de passe trouvé : {pwd}  (Algorithme : {algo})")
        else:
            print(f"[✘] Aucun mot de passe trouvé dans '{WORDLIST_PATH}'.")

if __name__ == "__main__":
    main()
