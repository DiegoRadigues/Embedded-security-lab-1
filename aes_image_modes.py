import os, sys, secrets, io
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --------- Utilitaires ---------
def to_ppm_bytes(img: Image.Image) -> bytes:
    """Convertit l'image PIL en PPM (P6) et renvoie les octets."""
    rgb = img.convert("RGB")
    with io.BytesIO() as buf:
        rgb.save(buf, format="PPM")
        return buf.getvalue()

def split_ppm_header_and_pixels(ppm_bytes: bytes):
    """Sépare l'en-tête ASCII du PPM (jusqu'au 3e saut de ligne après 'P6') et la zone pixels."""
    # En-tête PPM P6 : "P6\nWIDTH HEIGHT\nMAXVAL\n"
    # On cherche 3 sauts de ligne après 'P6'
    if not ppm_bytes.startswith(b"P6"):
        raise ValueError("Le flux n'est pas un PPM P6.")
    # indices des sauts de ligne
    nl_pos = []
    for i, b in enumerate(ppm_bytes[:1024]):  # l'en-tête est court
        if b == 0x0A:  # '\n'
            nl_pos.append(i)
            if len(nl_pos) == 3:
                break
    if len(nl_pos) < 3:
        raise ValueError("En-tête PPM invalide.")
    header_end = nl_pos[2] + 1
    header = ppm_bytes[:header_end]
    pixels = ppm_bytes[header_end:]
    return header, pixels

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len])*pad_len

def aes_encrypt(mode_name: str, key: bytes, data: bytes):
    """Chiffre data avec AES dans le mode demandé. Renvoie (ciphertext, extra_info_dict)."""
    backend = default_backend()
    if mode_name == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        padded = pkcs7_pad(data, 16)
        ct = encryptor.update(padded) + encryptor.finalize()
        # Pour garder la même taille de fichier, on tronque à la taille d'origine (visualisation uniquement).
        return ct[:len(data)], {"note": "ECB avec padding PKCS#7 tronqué pour conserver la taille."}

    elif mode_name == "CBC":
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padded = pkcs7_pad(data, 16)
        ct = encryptor.update(padded) + encryptor.finalize()
        return ct[:len(data)], {"iv": iv.hex(), "note": "CBC avec padding tronqué pour conserver la taille."}

    elif mode_name == "CTR":
        nonce = secrets.token_bytes(16)  # AES-CTR accepte un nonce/compteur de 128 bits
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return ct, {"nonce": nonce.hex()}

    elif mode_name == "GCM":
        nonce = secrets.token_bytes(12)  # 96 bits recommandé pour GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        # On n'utilise pas le tag ici car on ne déchiffre pas; on veut juste visualiser.
        return ct, {"nonce": nonce.hex(), "tag": encryptor.tag.hex()}
    else:
        raise ValueError("Mode non supporté")

def write_ppm(path_out: str, header: bytes, pixels_cipher: bytes):
    with open(path_out, "wb") as f:
        f.write(header)
        f.write(pixels_cipher)

# --------- Main ---------
def main():
    if len(sys.argv) < 2:
        print("Usage: python aes_image_modes.py /chemin/vers/image.jpg")
        sys.exit(1)

    in_path = sys.argv[1]
    if not os.path.exists(in_path):
        print("Fichier introuvable:", in_path)
        sys.exit(1)

    # 1) Charger l'image et obtenir un PPM (en-tête simple)
    img = Image.open(in_path)
    ppm_bytes = to_ppm_bytes(img)
    header, pixels = split_ppm_header_and_pixels(ppm_bytes)

    # 2) Générer une clé AES (256 bits)
    key = secrets.token_bytes(32)

    # 3) Chiffrer dans chaque mode
    out_dir = os.path.dirname(os.path.abspath(in_path)) or "."
    stem = os.path.splitext(os.path.basename(in_path))[0]

    modes_list = ["ECB", "CBC", "CTR", "GCM"]
    for mode_name in modes_list:
        ct, info = aes_encrypt(mode_name, key, pixels)
        out_path = os.path.join(out_dir, f"{stem}_AES_{mode_name}.ppm")
        write_ppm(out_path, header, ct)
        print(f"[OK] {mode_name} → {out_path}")
        if info:
            print("     Info:", info)

    print("\nNotes d’observation attendues :")
    print("- ECB : motifs résiduels visibles → À éviter absolument.")
    print("- CBC/CTR/GCM : rendu bruité (aucune structure perceptible).")

if __name__ == "__main__":
    main()
