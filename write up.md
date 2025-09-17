# Laboratoire 1 – Introduction à la Cryptographie

## 1. Modes de fonctionnement de l’AES

### Objectif
L’objectif de cette première partie était d’expérimenter les différents modes de chiffrement d’AES (ECB, CBC, CTR, GCM) sur une image afin d’observer leur comportement visuel.  

### Méthodologie
- **Préparation de l’image :** l’image de test (un perroquet) a été convertie en format PPM, ce qui permet de séparer aisément l’en-tête (dimensions, profondeur de couleur) du contenu binaire des pixels.  
- **Clé et paramètres :** une clé AES de 256 bits a été générée aléatoirement pour l’ensemble de l’expérience. Un IV/nonce distinct a été généré pour chaque mode CBC, CTR et GCM.  
- **Chiffrement :** les pixels ont été chiffrés en AES dans chacun des modes, puis réassemblés avec l’en-tête original afin de conserver un fichier PPM valide, visualisable directement.  
- **Comparaison :** les résultats ont été rassemblés dans une image 2×2 (ECB, CBC, CTR, GCM) pour une analyse comparative.

### Résultats
![Comparaison AES](perroquet_AES_comparison.png)

- **ECB :** malgré le chiffrement, on distingue encore des motifs résiduels correspondant aux grandes zones de couleur de l’image originale.  
- **CBC / CTR / GCM :** l’image est transformée en un bruit uniforme ; aucune information visuelle n’est perceptible.  

### Analyse
Le mode ECB chiffre chaque bloc indépendamment, ce qui révèle la structure des données en cas de répétition de motifs. Cela le rend totalement inadapté pour protéger des données présentant des redondances (images, fichiers structurés).  
Les modes CBC, CTR et GCM introduisent un aléa (IV ou compteur) qui rend chaque bloc dépendant du précédent (CBC) ou d’un flux pseudo-aléatoire (CTR/GCM), éliminant ainsi toute corrélation visible.  
Le mode **GCM**, en plus d’assurer la confidentialité, fournit une **authentification** via un tag, garantissant l’intégrité des données lors du déchiffrement.  

**Conclusion :**  
ECB ne doit jamais être utilisé en pratique. Pour des données nécessitant également une vérification d’intégrité, GCM est recommandé.

---

## 2. Capture The Flag (picoCTF)

### Mise en place
Un compte a été créé sur [picoCTF](https://picoctf.org/), et les défis de la catégorie cryptographie suivants ont été sélectionnés :
- `hashcrack`
- `interencdec`
- `The Numbers`
- `13`
- `Vigenere`
- `HideToSee`
- `Easy Peasy`
- `PowerAnalysis: Warmup`

Chaque défi a été documenté par un **write-up concis** comprenant :
- L’énoncé du challenge
- Les outils ou scripts utilisés
- La démarche de résolution
- Le flag obtenu

Ces notes permettent de justifier le raisonnement et de capitaliser les méthodes de résolution pour les laboratoires suivants.

## 2. HashCracking Automatique

**But :** retrouver des mots de passe à partir de leurs empreintes MD5, SHA-1, SHA-256.

Script utilisé : `hashcrack.py`

```bash
python hashcrack.py
```

Exemples :

```
Entrez le hash : 482c811da5d5b4bc6d497ffa98491e38
[i] Détection automatique → MD5
[✔] Mot de passe trouvé : password123

Entrez le hash : b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3
[i] Détection automatique → SHA1
[✔] Mot de passe trouvé : letmein

Entrez le hash : 916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745
[i] Détection automatique → SHA256
[✔] Mot de passe trouvé : qwerty098
```

⚠️ L’efficacité dépend de la wordlist (`rockyou.txt`). On cherche simplement si le hash correspond à un mot de la liste.

---

## 3. Interencdec

Fichier : `enc_flag`

Script : `solve_interencdec.py`

```bash
python solve_interencdec.py enc_flag
```

Sortie :

```
[+] Base64 décodé (étape 1)
[+] Base64 décodé (étape 2)
[i] Contenu après Base64 : wpjvJAM{jhlzhy_k3jy9wa3k_i204hkj6}

[✔] Flag détecté via Caesar(+19) :
picoCTF{caesar_d3cr9pt3d_b204adc6}
```

Explication : double **Base64 decode** suivi d’un **chiffre de César** (+19).

---

## 4. The Numbers (A1Z26)

But : convertir des séquences de nombres en lettres (A1Z26).

Script : `solve_the_numbers.py`

Avec OCR sur l’image :

```bash
python solve_the_numbers.py --image the_numbers.png
```

Pipeline :

- OCR Tesseract (avec prétraitements)
- Découpage automatique des nombres
- Conversion en lettres
- Détection du motif `picoCTF{...}`

Résultat : reconstruction du flag.

---

## 5. ROT13

Challenge :

```
cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}
```

Script : `solve_13.py`

```bash
python solve_13.py "cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}"
```

Résultat :

```
picoCTF{not_too_bad_of_a_problem}
```

---

## 6. Vigenère

Message chiffré :

```
rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_f85729e7}
```

Clé : `CYLAB`

Script : `solve_vigenere.py`

```bash
python solve_vigenere.py
# Entrez le message et la clé lorsqu'il le demande
```

Résultat :

```
picoCTF{D0NT_US3_V1G3N3R3_C1PH3R_f85729e7}
```

---

## 7 HideToSee (stéganographie + Atbash)

**Énoncé.**\
\> *How about some hide and seek heh? Look at this image here.*\
On nous fournit une image JPEG. L'aperçu montre une roue de chiffrement
intitulée **"Atbash Cipher"**.

#### Hypothèse / Indice

L'image d'illustration elle-même pointe vers **Atbash** (substitution
miroir : a↔z, b↔y, ...). Je m'attends donc à : 1) des données **cachées
dans l'image** (stéganographie) ;\
2) un **message chiffré en Atbash** à l'intérieur ;\
3) le **flag** après déchiffrement.

#### Outils

-   **Windows (sans droits admin) :** `steghide.exe` (version portable)\
-   **PowerShell** (natif)\
-   *(Optionnel Linux/WSL : `steghide`, `strings`, `exiftool`,
    `binwalk`)*

#### Démarche (Windows/PowerShell)

1)  **Récupérer steghide portable**\
    Télécharger l'archive Windows depuis le site officiel, extraire
    `steghide.exe`, et le placer **dans le même dossier** que l'image
    `hide_to_see.jpg`.

2)  **Extraire le contenu caché (sans passphrase)**\
    Dans PowerShell, depuis le dossier contenant l'image :

    ``` powershell
    .\steghide.exe extract -sf .\hide_to_see.jpg
    ```

    À la demande de passphrase, **appuyer Entrée**.\
    Sortie observée :

        écriture des données extraites dans "encrypted.txt".

3)  **Lire le fichier extrait**

    ``` powershell
    Get-Content .\encrypted.txt
    ```

    Contenu obtenu :

        krxlXGU{zgyzhs_xizxp_8z0uvwwx}

4)  **Déchiffrer en Atbash (respect de la casse)**

    ``` powershell
    $in = "krxlXGU{zgyzhs_xizxp_8z0uvwwx}"
    $alpha = "abcdefghijklmnopqrstuvwxyz"
    $map = @{}
    for($i=0;$i -lt 26;$i++){ $map[$alpha[$i]] = $alpha[25-$i] }

    $decoded = -join ($in.ToCharArray() | ForEach-Object {
      if($_ -match '[A-Z]'){ [char]::ToUpper($map[[char]::ToLower($_)]) }
      elseif($_ -match '[a-z]'){ $map[$_] } else { $_ }
    })
    $decoded
    ```

    Résultat :

        picoCTF{atbash_crack_8a0feddc}

#### Démarche (alternative Linux/WSL)

``` bash
steghide extract -sf hide_to_see.jpg    # Entrée quand il demande la passphrase
cat encrypted.txt                        # krxlXGU{zgyzhs_xizxp_8z0uvwwx}
```

Petit one-liner Python pour Atbash (si tu préfères) :

``` python
s="krxlXGU{zgyzhs_xizxp_8z0uvwwx}"
alpha="abcdefghijklmnopqrstuvwxyz"
table=str.maketrans(alpha+alpha.upper(), alpha[::-1]+alpha[::-1].upper())
print(s.translate(table))  # picoCTF{atbash_crack_8a0feddc}
```

#### Points d'apprentissage

-   **Stéganographie "classique" sur JPEG** : `steghide extract` sans
    passphrase est un réflexe sur picoCTF.\
-   **Indice visuel = piste crypto** : l'image "Atbash Cipher" oriente
    directement la phase de déchiffrement.\
-   **Respect de la casse** : certains challenges exigent une sortie
    sensible à la casse ; le décodeur Atbash l'a conservée.

#### Flag

    picoCTF{atbash_crack_8a0feddc}


    # picoCTF - Easy Peasy (Crypto)

**Catégorie :** Cryptographie (40 pts)\
**Objectif :** retrouver le flag en exploitant la réutilisation du pad
(OTP).

------------------------------------------------------------------------

## 8 Easy Peasy
### Énoncé

> *A one-time pad is unbreakable, but can you manage to recover the
> flag?*\
> *(Wrap with picoCTF{})*\
> nc mercury.picoctf.net 11188

On obtient directement le **flag chiffré** au démarrage, puis le service
propose de chiffrer des messages arbitraires en réutilisant le même pad
circulaire (50000 octets).

------------------------------------------------------------------------

### Vulnérabilité

Le code serveur (fourni ou récupéré sur GitHub) montre :

-   `startup()` chiffre le flag avec le pad à partir de la position 0 et
    avance le curseur.
-   `encrypt()` chiffre la donnée utilisateur et **avance le curseur**,
    avec un wrap‑around si la fin de clé est atteinte.

Ainsi, en envoyant exactement `50000 - len(flag_ct)` octets, le curseur
revient à 0. Si l'on envoie ensuite le **cipher du flag** comme
*plaintext*, le service renvoie :

\[(P `\oplus `{=tex}K) `\oplus `{=tex}K = P\]

c'est‑à‑dire le flag en clair.

------------------------------------------------------------------------

### Script de résolution

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import remote, context, log
import binascii, sys

HOST = "mercury.picoctf.net"
PORT = 11188          # adapter si nécessaire
KEY_LEN = 50000       # longueur du pad
MAX_CHUNK = 1000      # taille des bursts
context.log_level = "info"  # "debug" pour tout voir

def recv_until_flag_line(r):
    log.info("Attente de 'This is the encrypted flag!'…")
    r.recvuntil(b"This is the encrypted flag!\n")
    flag_hex = r.recvline(keepends=False)
    flag_ct = binascii.unhexlify(flag_hex.strip())
    log.info(f"Cipher du flag: {flag_hex.decode()} ({len(flag_ct)} octets)")
    return flag_ct

def consume_pad_until_wrap(r, need):
    log.info(f"Consommation pour wrap-around: {need} octets")
    remaining = need
    while remaining > 0:
        chunk = min(MAX_CHUNK, remaining)
        payload = b"a" * chunk
        r.sendlineafter(b"What data would you like to encrypt? ", payload)
        r.recvuntil(b"Here ya go!\n")
        _ = r.recvline(keepends=False)
        remaining -= chunk

def reencrypt_and_recover_flag(r, flag_ct):
    log.info("Ré-envoi du chiffre du flag pour obtenir le flag en clair…")
    r.sendafter(b"What data would you like to encrypt? ", flag_ct + b"\n")
    r.recvuntil(b"Here ya go!\n")
    plain_hex = r.recvline(keepends=False)
    candidate = binascii.unhexlify(plain_hex.strip()).decode()
    return candidate if candidate.startswith("picoCTF{") else f"picoCTF{{{candidate}}}"

def main():
    r = remote(HOST, PORT)
    flag_ct = recv_until_flag_line(r)
    need = (KEY_LEN - len(flag_ct)) % KEY_LEN
    if need:
        consume_pad_until_wrap(r, need)
    flag = reencrypt_and_recover_flag(r, flag_ct)
    print("\n==================== FLAG ====================")
    print(flag)
    print("=============================================")
    r.close()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error(f"Erreur: {e}")
        sys.exit(1)
```

------------------------------------------------------------------------

### Exemple de sortie

    [*] Cipher du flag (hex): 551e6c4c5e55644b56566d1b5100153d4004026a4b52066b4a5556383d4b0007
    [*] Taille du cipher du flag: 32 octets
    [*] Consommation pour wrap-around: 49968 octets
    [*] Ré-envoi du chiffre du flag pour obtenir le flag en clair…
    [+] Flag en clair (hex) reçu: 3739303466663833306631633562626138663736333730373234376261336531

    ==================== FLAG ====================
    picoCTF{7904ff830f1c5bba8f763707247ba3e1}
    =============================================

------------------------------------------------------------------------

### Points clés

-   **Réutilisation de pad = fail** : un OTP est sûr seulement s'il
    n'est utilisé qu'une fois.
-   **Wrap-around** : le curseur revenant à zéro, on retrouve le même
    keystream que pour le flag.
-   **Double XOR** : ((P`\oplus `{=tex}K) `\oplus `{=tex}K = P) nous
    rend directement le flag.