#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import remote, context, log
import binascii
import sys

# ========= Réglages =========
HOST = "mercury.picoctf.net"
PORT = 11188          # adapte si besoin
KEY_LEN = 50000       # longueur du pad d’après le code serveur
MAX_CHUNK = 1000      # taille des bursts pour “manger” le pad
context.log_level = "info"  # "debug" pour tout voir
# ===========================

def recv_until_flag_line(r):
    """
    Attend le marqueur 'This is the encrypted flag!' puis lit la ligne suivante
    qui est l'hex du flag chiffré. Retourne (flag_hex_str, flag_bytes).
    """
    log.info("Attente de 'This is the encrypted flag!'…")
    r.recvuntil(b"This is the encrypted flag!\n")
    flag_hex = r.recvline(keepends=False)
    if not flag_hex:
        raise RuntimeError("Pas de ligne après le marqueur du flag.")
    if any(c not in b"0123456789abcdefABCDEF" for c in flag_hex):
        raise RuntimeError(f"Ligne inattendue après le marqueur (pas de hex): {flag_hex[:60]!r}")
    flag_ct = binascii.unhexlify(flag_hex.strip())
    log.info(f"Cipher du flag (hex): {flag_hex.decode()}")
    log.info(f"Taille du cipher du flag: {len(flag_ct)} octets")
    return flag_hex.decode(), flag_ct

def consume_pad_until_wrap(r, need):
    """
    Consomme exactement 'need' octets de pad en envoyant des payloads ASCII, et
    lit/ignore les réponses. Utilise le prompt standard du service.
    """
    log.info(f"Consommation pour wrap-around: {need} octets")
    remaining = need
    while remaining > 0:
        chunk = min(MAX_CHUNK, remaining)
        payload = b"a" * chunk
        # Le service attend: "What data would you like to encrypt? "
        r.sendlineafter(b"What data would you like to encrypt? ", payload)
        r.recvuntil(b"Here ya go!\n")
        _ = r.recvline(keepends=False)  # jeter le ciphertext retourné
        remaining -= chunk
        log.debug(f" - mangé {chunk}, reste {remaining}")

def reencrypt_and_recover_flag(r, flag_ct):
    """
    Envoie le *cipher du flag* comme plaintext (bytes) après wrap-around.
    Le service renvoie le flag en clair, en HEX sur une ligne après 'Here ya go!'.
    """
    log.info("Ré-envoi du chiffre du flag pour obtenir le flag en clair…")
    # Important: envoyer les BYTES bruts + newline, sans convertir (latin-1 peut aussi marcher,
    # mais bytes + '\n' est plus direct avec pwntools).
    r.sendafter(b"What data would you like to encrypt? ", flag_ct + b"\n")

    r.recvuntil(b"Here ya go!\n")
    plain_hex = r.recvline(keepends=False)
    if not plain_hex or any(c not in b"0123456789abcdefABCDEF" for c in plain_hex):
        raise RuntimeError("Réponse inattendue: pas de ligne HEX après 'Here ya go!'")
    log.success(f"Flag en clair (hex) reçu: {plain_hex.decode()}")
    try:
        # Beaucoup d’instances renvoient le flag comme texte hex (ex: 'deadbeef...').
        candidate = binascii.unhexlify(plain_hex.strip())  # bytes du flag “texte”
        try:
            txt = candidate.decode().strip()
            # Si c'est déjà picoCTF{…}, garde tel quel; sinon emballe.
            return txt if (txt.startswith("picoCTF{") and txt.endswith("}")) else f"picoCTF{{{txt}}}"
        except UnicodeDecodeError:
            # Pas décodable proprement → enrobe l’hex directement
            return f"picoCTF{{{plain_hex.decode()}}}"
    except binascii.Error:
        # La ligne retournée n’était pas hex valide (peu probable) → tente en texte direct
        try:
            txt = plain_hex.decode().strip()
            return txt if (txt.startswith("picoCTF{") and txt.endswith("}")) else f"picoCTF{{{txt}}}"
        except UnicodeDecodeError:
            return f"picoCTF{{{plain_hex.decode(errors='ignore')}}}"

def main():
    log.info(f"Connexion à {HOST}:{PORT}")
    r = remote(HOST, PORT)

    # 1) Lire le chiffre du flag
    flag_hex_str, flag_ct = recv_until_flag_line(r)

    # 2) Calculer le nombre d’octets à consommer pour revenir à l’index 0
    need = (KEY_LEN - len(flag_ct)) % KEY_LEN
    if need:
        consume_pad_until_wrap(r, need)
    else:
        log.info("Déjà aligné au début du pad (need=0).")

    # 3) Ré-encrypter le chiffre du flag pour obtenir le flag en clair
    flag = reencrypt_and_recover_flag(r, flag_ct)

    print("\n==================== FLAG ====================")
    print(flag)
    print("=============================================\n")

    r.close()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error(f"Erreur: {e}")
        sys.exit(1)
