#!/usr/bin/env python3
import base64
import codecs
import sys
import re
from typing import Tuple

def try_b64(s: bytes) -> Tuple[bool, bytes]:
    """
    Tente un décodage Base64 strict. Retourne (ok, data_decoded).
    """
    # Nettoyage: retirer espaces/nouveaux lignes
    compact = b"".join(s.split())
    try:
        out = base64.b64decode(compact, validate=True)
        return True, out
    except Exception:
        return False, b""

def strip_python_bytes_literal(s: str) -> str:
    """
    Si s ressemble à "b'...'" ou b"...", récupère l'intérieur.
    Sinon, renvoie s tel quel.
    """
    m = re.fullmatch(r"""b['"](.+?)['"]""", s.strip())
    return m.group(1) if m else s

def to_str(b: bytes) -> str:
    # essaie utf-8 puis latin-1
    for enc in ("utf-8", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            pass
    # si impossible: représentation hex
    return b.hex()

def rot_n(s: str, n: int) -> str:
    """
    César générique sur alphabet ASCII (lettres A-Z et a-z).
    """
    out = []
    for ch in s:
        c = ord(ch)
        if 65 <= c <= 90:      # A-Z
            out.append(chr((c - 65 + n) % 26 + 65))
        elif 97 <= c <= 122:   # a-z
            out.append(chr((c - 97 + n) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)

def try_rot13_and_caesar(s: str) -> Tuple[bool, str, str]:
    """
    Tente d'abord ROT13. Si on trouve 'picoCTF{' → succès.
    Sinon, teste tous les décalages César 0..25 et renvoie le premier
    qui contient 'picoCTF{'.
    Retourne (ok, algo, résultat).
    """
    r13 = codecs.decode(s, "rot_13")
    if "picoCTF{" in r13:
        return True, "ROT13", r13

    for n in range(26):
        rn = rot_n(s, n)
        if "picoCTF{" in rn:
            return True, f"Caesar(+{n})", rn

    return False, "", s

def solve_file(path: str):
    print(f"[i] Lecture du fichier: {path}")
    data = open(path, "rb").read()
    current = data
    step = 0

    # 1) Boucle: décodage Base64 jusqu'à ce que ça ne passe plus
    while True:
        ok, dec = try_b64(current)
        if not ok:
            # si c'était du texte avec "b'...'", on l’extrait et on réessaie
            try_text = to_str(current)
            inner = strip_python_bytes_literal(try_text)
            if inner != try_text:
                # on a extrait l'intérieur → retenter base64
                current = inner.encode("utf-8")
                continue
            # plus rien à décoder en Base64
            break

        step += 1
        print(f"[+] Base64 décodé (étape {step}) → {len(dec)} octets")
        current = dec

        # si le décodage produit du texte style "b'...'", on extrait immédiatement
        as_text = to_str(current)
        inner = strip_python_bytes_literal(as_text)
        if inner != as_text:
            current = inner.encode("utf-8")

    # 2) À ce stade, current contient probablement du texte
    text = to_str(current)
    print(f"[i] Contenu après Base64 : {text}")

    # 3) Tentative ROT13 / César si le flag n'est pas encore en clair
    if "picoCTF{" in text:
        print("\n[✔] Flag détecté (sans ROT) :")
        print(text)
        return

    ok, algo, out = try_rot13_and_caesar(text)
    if ok:
        print(f"\n[✔] Flag détecté via {algo} :")
        print(out)
    else:
        print("\n[!] Aucun flag 'picoCTF{' détecté automatiquement.")
        print("    Résultat brut :")
        print(text)

def main():
    if len(sys.argv) < 2:
        print("Usage: python solve_interencdec.py <chemin_du_fichier_enc_flag>")
        print(r'Ex: python solve_interencdec.py "C:\Users\diego\Documents\5MEO\Embedded security\Lab1\enc_flag"')
        sys.exit(1)
    solve_file(sys.argv[1])

if __name__ == "__main__":
    main()
