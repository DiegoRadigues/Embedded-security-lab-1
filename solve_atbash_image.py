#!/usr/bin/env python3
import re, os, sys, string

def atbash(s: str) -> str:
    A, Z = ord('A'), ord('Z')
    a, z = ord('a'), ord('z')
    out = []
    for ch in s:
        c = ord(ch)
        if A <= c <= Z:
            out.append(chr(Z - (c - A)))
        elif a <= c <= z:
            out.append(chr(z - (c - a)))
        else:
            out.append(ch)
    return "".join(out)

def rot_n(s: str, n: int) -> str:
    out = []
    for ch in s:
        if 'A' <= ch <= 'Z':
            out.append(chr((ord(ch)-65+n)%26 + 65))
        elif 'a' <= ch <= 'z':
            out.append(chr((ord(ch)-97+n)%26 + 97))
        else:
            out.append(ch)
    return "".join(out)

def candidates_from_text(t: str):
    cands = []
    # 1) brut
    cands.append(("RAW", t))
    # 2) Atbash
    cands.append(("ATBASH", atbash(t)))
    # 3) ROT13
    cands.append(("ROT13", rot_n(t,13)))
    # 4) Tous les César
    for n in range(26):
        cands.append((f"CAESAR(+{n})", rot_n(t, n)))
    return cands

def ocr_image(path: str) -> str:
    from PIL import Image, ImageOps, ImageFilter
    import pytesseract

    # pointer Tesseract si besoin (Windows)
    default_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.name == "nt" and os.path.exists(default_path):
        pytesseract.pytesseract.tesseract_cmd = default_path

    img = Image.open(path)
    g = ImageOps.grayscale(img)
    g = ImageOps.autocontrast(g)
    g = g.filter(ImageFilter.MedianFilter(size=3))
    bw = g.point(lambda p: 255 if p > 160 else 0)

    # conserver espaces et chiffres/accollades
    config = r'--psm 6 -c preserve_interword_spaces=1 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_'
    text = pytesseract.image_to_string(bw, config=config)
    # petit nettoyage
    text = text.replace('’', "'").replace('“','"').replace('”','"')
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def main():
    if len(sys.argv) < 2:
        print("Usage: python solve_atbash_image.py <chemin_image>")
        print(r'Ex:    python solve_atbash_image.py "C:\Users\diego\Documents\5MEO\Embedded security\Lab1\atbash.jpg"')
        sys.exit(1)

    image_path = sys.argv[1]
    text = ocr_image(image_path)
    print("[i] Texte OCR :", text)

    found = []
    for tag, out in candidates_from_text(text):
        if "picoCTF{" in out or "PICOCTF{" in out:
            found.append((tag, out))

    print("\n=== Résultats ===")
    if found:
        for tag, out in found:
            print(f"[{tag}] -> {out}")
    else:
        # si rien ne match, on affiche quand même les 3 principaux pour inspection
        cand = dict(candidates_from_text(text))
        print("[RAW]   ", cand["RAW"])
        print("[ATBASH]", cand["ATBASH"])
        print("[ROT13] ", cand["ROT13"])

if __name__ == "__main__":
    main()
