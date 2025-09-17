#!/usr/bin/env python3
import sys, re, base64, struct, os
from pathlib import Path

MAGICS = [
    (b"\x50\x4B\x03\x04", "ZIP"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"GIF89a", "GIF"),
    (b"%PDF", "PDF"),
    (b"\x1F\x8B\x08", "GZIP"),
]

def ascii_strings(b, minlen=6):
    for m in re.finditer(rb"[ -~]{%d,}" % minlen, b):
        yield m.start(), m.group(0)

def try_b64_chunks(b):
    hits = []
    for m in re.finditer(rb"[A-Za-z0-9+/]{16,}={0,2}", b):
        try:
            dec = base64.b64decode(m.group(0), validate=True)
            s = dec.decode("utf-8", "ignore")
            if "picoCTF{" in s:
                hits.append(s)
        except Exception:
            pass
    return hits

def parse_jpeg_segments(raw: bytes):
    if not raw.startswith(b"\xFF\xD8"): 
        print("[!] Pas un JPEG (pas de SOI)."); 
        return []
    segs = []
    i = 2
    while i + 4 <= len(raw):
        if raw[i] != 0xFF:
            i += 1; 
            continue
        marker = raw[i+1]
        i += 2
        if marker == 0xD9:  # EOI
            break
        if marker == 0xDA:  # SOS (début des scans) => on s'arrête avant les MCUs
            # on pourrait chercher EOI mais les données ne sont pas segmentées après SOS
            break
        if i + 2 > len(raw): break
        seglen = struct.unpack(">H", raw[i:i+2])[0]
        i += 2
        if seglen < 2 or i + seglen - 2 > len(raw): break
        data = raw[i:i+seglen-2]
        i += seglen - 2
        segs.append((marker, data))
    return segs

def main():
    if len(sys.argv) < 2:
        print("Usage: python jpeg_hunt_plus.py <image.jpg>")
        sys.exit(1)
    p = Path(sys.argv[1])
    raw = p.read_bytes()
    outdir = p.with_suffix("")  # ex: atbash
    segdir = Path(str(outdir) + "_segments")
    segdir.mkdir(exist_ok=True)

    print("[i] Scan brut (flux complet)…")
    found = False
    for _, s in ascii_strings(raw):
        ds = s.decode("utf-8", "ignore")
        if "picoCTF{" in ds:
            print("[✔] Flux brut:", ds)
            found = True
            break
    if not found:
        for s in try_b64_chunks(raw):
            print("[✔] Flux brut (base64→texte):", s)
            found = True

    print("[i] Analyse des segments JPEG…")
    segs = parse_jpeg_segments(raw)
    print(f"[i] {len(segs)} segments (avant SOS).")
    for idx, (marker, data) in enumerate(segs, 1):
        name = f"FF{marker:02X}"
        out = segdir / f"{idx:02d}_{name}.bin"
        out.write_bytes(data)
        # log
        if marker == 0xFE:
            print(f"  - {idx:02d} {name}  COM  len={len(data)} -> {out.name}")
        elif 0xE0 <= marker <= 0xEF:
            print(f"  - {idx:02d} {name}  APP{marker-0xE0} len={len(data)} -> {out.name}")
        else:
            print(f"  - {idx:02d} {name}  len={len(data)} -> {out.name}")

        # strings
        for _, s in ascii_strings(data):
            ds = s.decode("utf-8", "ignore")
            if "picoCTF{" in ds:
                print(f"[✔] {name}/strings:", ds); found = True
        # base64
        for s in try_b64_chunks(data):
            print(f"[✔] {name}/base64:", s); found = True

        # carve magics dans le segment
        for sig, label in MAGICS:
            pos = data.find(sig)
            if pos != -1:
                carved = segdir / f"{idx:02d}_{name}.{label.lower()}"
                carved.write_bytes(data[pos:])
                print(f"[i] {name}: détecté {label} @+{pos} → dump: {carved}")

    # carve global (fichier embarqué collé après SOS)
    for sig, label in MAGICS:
        pos = raw.find(sig)
        if pos != -1:
            carved = p.with_suffix(p.suffix + f".{label.lower()}")
            carved.write_bytes(raw[pos:])
            print(f"[i] Flux: détecté {label} @ {pos} → dump: {carved}")

    if not found:
        print("\n[!] Rien d'évident trouvé. Ouvre les fichiers dans", segdir, 
              "et jette un œil aux .bin, ou essaie steghide/exiftool.")

if __name__ == "__main__":
    main()
