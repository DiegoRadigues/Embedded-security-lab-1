#!/usr/bin/env python3
import sys
import codecs

def rot13(s: str) -> str:
    return codecs.decode(s, 'rot_13')

def main():
    if len(sys.argv) < 2:
        print("Usage: python solve_13.py '<texte_rot13>'")
        print("Ex:    python solve_13.py 'cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}'")
        return
    s = sys.argv[1]
    print(rot13(s))

if __name__ == "__main__":
    main()
