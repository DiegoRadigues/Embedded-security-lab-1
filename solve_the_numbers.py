#!/usr/bin/env python3
import re, argparse
from typing import List, Optional, Tuple

# ---- A1Z26 ----
def a1z26_decode_from_tokens(tokens: List[str]) -> str:
    out = []
    for t in tokens:
        if t.isdigit():
            n = int(t)
            out.append(chr(64 + n) if 1 <= n <= 26 else t)
        else:
            out.append(t)
    return "".join(out)

def tokenize_loose(s: str) -> List[str]:
    # conserve { } _ et sépare les nombres ; supprime espaces
    tokens = []
    for m in re.finditer(r"\d+|[{}_\-]|[A-Za-z]+|.", s):
        tok = m.group(0)
        if tok.isspace():
            continue
        tokens.append(tok)
    return tokens

# Découpe une chaîne de chiffres collés en nombres 1..26 (A1Z26),
# en privilégiant les 2 chiffres quand possible (16= P etc.)
def split_digits_a1z26(digits: str) -> Optional[List[str]]:
    n = len(digits)
    dp: List[Optional[List[str]]] = [None]*(n+1)
    dp[0] = []
    for i in range(n):
        if dp[i] is None: 
            continue
        # 1 chiffre
        v1 = int(digits[i])
        if 1 <= v1 <= 9:
            cand = dp[i] + [digits[i:i+1]]
            if dp[i+1] is None:
                dp[i+1] = cand
        # 2 chiffres
        if i+1 < n:
            v2 = int(digits[i:i+2])
            if 10 <= v2 <= 26:
                cand = dp[i] + [digits[i:i+2]]
                if dp[i+2] is None:
                    dp[i+2] = cand
    return dp[n]

# Petit heuristique : essaie de repérer motif FLAG une fois décodé
def looks_like_flag(s: str) -> bool:
    return "PICOCTF{" in s or "picoCTF{" in s

# ---- OCR ----
def run_ocr_all_configs(image_path: str) -> List[str]:
    from PIL import Image, ImageOps, ImageFilter
    import pytesseract, os

    default_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if os.name == "nt" and os.path.exists(default_path):
        pytesseract.pytesseract.tesseract_cmd = default_path

    img = Image.open(image_path)

    # Prétraitements
    g = ImageOps.grayscale(img)
    g = ImageOps.autocontrast(g)
    g = g.filter(ImageFilter.MedianFilter(size=3))
    bw = g.point(lambda p: 255 if p > 160 else 0)

    configs = [
        r'--psm 6 -c preserve_interword_spaces=1 -c tessedit_char_whitelist=0123456789 {}_',
        r'--psm 7 -c preserve_interword_spaces=1 -c tessedit_char_whitelist=0123456789 {}_',
        r'--psm 11 -c tessedit_char_whitelist=0123456789 {}_',
        r'--psm 6',
    ]
    results = []
    for cfg in configs:
        txt = pytesseract.image_to_string(bw, config=cfg)
        # nettoyage léger
        txt = txt.replace('O','0').replace('o','0')
        txt = re.sub(r'[^\d{}\s_]+', ' ', txt)
        txt = re.sub(r'\s+', ' ', txt).strip()
        if txt and txt not in results:
            results.append(txt)
    return results

def try_full_pipeline_from_text(raw: str) -> Tuple[str, str]:
    # 1) si séparateurs présents, chemin simple
    tokens = tokenize_loose(raw)
    decoded = a1z26_decode_from_tokens(tokens)
    if looks_like_flag(decoded):
        return raw, decoded

    # 2) si l’OCR a tout collé en une suite de chiffres, essayer découpe A1Z26
    only_digits = re.fullmatch(r"\d+", raw.replace(" ", ""))
    if only_digits:
        digits = raw.replace(" ", "")
        split = split_digits_a1z26(digits)
        if split:
            decoded2 = a1z26_decode_from_tokens(split)
            # injecter les accolades si l’image en contenait (on les ajoute sinon pour flag)
            if "{" not in decoded2 and "}" not in decoded2 and decoded2.startswith("PICOCTF"):
                decoded2 = decoded2[:7] + "{" + decoded2[7:] + "}"
            return " ".join(split), decoded2

    # 3) retour par défaut
    return raw, decoded

def main():
    import argparse
    p = argparse.ArgumentParser(description="The Numbers (A1Z26) avec OCR robuste et découpe auto.")
    p.add_argument("--text", help="Texte des nombres (ex: '16 9 3 15 3 20 6 { 20 8 ... }').")
    p.add_argument("--image", help="Chemin de l'image à lire par OCR.")
    args = p.parse_args()

    if not args.text and not args.image:
        p.error("Fournissez --text ou --image")

    candidates = []
    if args.text:
        candidates = [args.text]
    else:
        try:
            candidates = run_ocr_all_configs(args.image)
        except Exception as e:
            print("[!] Erreur OCR :", e)
            return

    best_in, best_out = "", ""
    for cand in candidates:
        tokens_in, decoded = try_full_pipeline_from_text(cand)
        print("\n[i] Essai OCR/texte :", cand)
        print("    Tokens/segmentation :", tokens_in)
        print("    Décodé :", decoded)
        if looks_like_flag(decoded):
            best_in, best_out = tokens_in, decoded
            break

    print("\n=== Résultat ===")
    if best_out:
        print("Entrée :", best_in)
        print("Sortie :", best_out)
        print("Flag   :", best_out.replace("PICOCTF", "picoCTF"))
    else:
        # pas de motif flag, mais on donne la meilleure tentative
        print("Aucun flag détecté automatiquement.")
        if candidates:
            tokens_in, decoded = try_full_pipeline_from_text(candidates[0])
            print("Entrée :", tokens_in)
            print("Sortie :", decoded)

if __name__ == "__main__":
    main()
