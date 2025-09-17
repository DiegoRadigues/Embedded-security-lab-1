import os, sys
from PIL import Image, ImageDraw, ImageFont

def add_label(img, text):
    pad_h = 40
    labeled = Image.new("RGB", (img.width, img.height + pad_h), (255, 255, 255))
    labeled.paste(img, (0, pad_h))
    d = ImageDraw.Draw(labeled)
    try:
        font = ImageFont.truetype("arial.ttf", 20)
    except:
        font = ImageFont.load_default()
    # Compatibilité Pillow : préférer textbbox si dispo
    if hasattr(d, "textbbox"):
        left, top, right, bottom = d.textbbox((0, 0), text, font=font)
        tw, th = right - left, bottom - top
    else:
        tw, th = d.textsize(text, font=font)
    d.text(((img.width - tw) // 2, (pad_h - th) // 2), text, fill=(0, 0, 0), font=font)
    return labeled

def main():
    if len(sys.argv) < 2:
        print("Usage: python make_comparison.py /path/to/perroquet_AES_ECB.ppm")
        sys.exit(1)
    first_path = sys.argv[1]
    folder = os.path.dirname(first_path) if os.path.isfile(first_path) else first_path

    names = ["ECB", "CBC", "CTR", "GCM"]
    files = [os.path.join(folder, f"perroquet_AES_{n}.ppm") for n in names]
    for f in files:
        if not os.path.exists(f):
            print("Fichier manquant:", f)
            return

    imgs = [Image.open(f).convert("RGB") for f in files]
    w, h = imgs[0].size
    imgs = [im.resize((w, h)) for im in imgs]
    labeled = [add_label(im, n) for im, n in zip(imgs, names)]

    grid_w = w * 2
    grid_h = (h + 40) * 2
    canvas = Image.new("RGB", (grid_w, grid_h), (255, 255, 255))
    canvas.paste(labeled[0], (0, 0))
    canvas.paste(labeled[1], (w, 0))
    canvas.paste(labeled[2], (0, h + 40))
    canvas.paste(labeled[3], (w, h + 40))

    out_path = os.path.join(folder, "perroquet_AES_comparison.png")
    canvas.save(out_path)
    print("[OK] Image de comparaison générée →", out_path)

if __name__ == "__main__":
    main()
