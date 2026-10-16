#!/usr/bin/env python3
"""
IDN Homograph Attack - Demo & Detector
========================================
Tujuan: EDUKASI & DEFENSIVE SECURITY.
Script ini TIDAK mendaftarkan domain apapun, TIDAK membuat halaman phishing,
dan TIDAK melakukan request ke domain manapun. Murni untuk:
  1. Mendemonstrasikan bagaimana karakter Unicode (Cyrillic/Greek/dll)
     bisa terlihat identik dengan huruf Latin -> IDN Homograph Attack.
  2. Mendeteksi apakah sebuah domain mengandung campuran script
     yang mencurigakan (mixed-script / confusable characters).

Gunakan bagian detector ini untuk defensive monitoring: cek domain
yang mencurigakan sebelum diklik, atau integrasikan ke email gateway /
DNS filtering internal.

Author: Demo project untuk pembelajaran pentest/security awareness.
Project by https://github.com/fahmipentest
"""

import sys
import argparse
import unicodedata
import idna  # pip install idna

# ---------------------------------------------------------------------------
# BAGIAN 1: TABEL KARAKTER HOMOGLYPH (contoh paling umum disalahgunakan)
# ---------------------------------------------------------------------------
# Peta: huruf Latin -> karakter dari script lain yang terlihat identik/mirip
HOMOGLYPH_MAP = {
    "a": "а",   # Cyrillic Small Letter A (U+0430)
    "e": "е",   # Cyrillic Small Letter Ie (U+0435)
    "o": "о",   # Cyrillic Small Letter O (U+043E)
    "p": "р",   # Cyrillic Small Letter Er (U+0440)
    "c": "с",   # Cyrillic Small Letter Es (U+0441)
    "x": "х",   # Cyrillic Small Letter Ha (U+0445)
    "y": "у",   # Cyrillic Small Letter U (U+0443)
    "i": "і",   # Cyrillic/Ukrainian Dotted I (U+0456)
    "s": "ѕ",   # Cyrillic Dze (U+0455)
    "j": "ј",   # Cyrillic Je (U+0458)
}

# Rentang blok Unicode yang sering dipakai utk homoglyph attack.
# Dipakai oleh detector utk menandai "mixed script".
SUSPICIOUS_RANGES = {
    "Cyrillic": (0x0400, 0x04FF),
    "Greek": (0x0370, 0x03FF),
    "Armenian": (0x0530, 0x058F),
}


def char_script(ch: str) -> str:
    """Kembalikan nama block Unicode dari sebuah karakter (sederhana)."""
    cp = ord(ch)
    if cp < 128:
        return "Latin/ASCII"
    for name, (lo, hi) in SUSPICIOUS_RANGES.items():
        if lo <= cp <= hi:
            return name
    return "Other"


# ---------------------------------------------------------------------------
# BAGIAN 2: GENERATOR CONTOH DOMAIN HOMOGRAPH (untuk demonstrasi visual)
# ---------------------------------------------------------------------------
def generate_homograph_variant(domain: str) -> str:
    """
    Ganti SATU karakter Latin pada domain dengan padanan homoglyph-nya,
    kalau tersedia di HOMOGLYPH_MAP. Ini hanya untuk DEMO visual,
    bukan untuk dipakai mendaftarkan domain sungguhan.
    """
    name, _, tld = domain.rpartition(".")
    chars = list(name)
    for i, c in enumerate(chars):
        if c.lower() in HOMOGLYPH_MAP:
            chars[i] = HOMOGLYPH_MAP[c.lower()]
            break  # cukup 1 karakter diganti, supaya tetap "identik" di mata
    fake_name = "".join(chars)
    return f"{fake_name}.{tld}"


def to_punycode(domain: str) -> str:
    """Konversi domain Unicode -> Punycode (xn--...) sesuai standar IDNA."""
    try:
        return idna.encode(domain).decode("ascii")
    except idna.IDNAError as e:
        return f"[gagal encode: {e}]"


# ---------------------------------------------------------------------------
# BAGIAN 3: DETECTOR - analisa domain mencurigakan
# ---------------------------------------------------------------------------
def analyze_domain(domain: str) -> dict:
    """
    Analisa sebuah domain (bisa dalam bentuk unicode atau xn--punycode)
    dan kembalikan laporan: apakah mixed-script, karakter apa saja yang
    mencurigakan, dan representasi aslinya.
    """
    report = {
        "input": domain,
        "is_punycode_input": domain.startswith("xn--") or ".xn--" in domain,
        "decoded_unicode": None,
        "punycode": None,
        "scripts_found": set(),
        "suspicious_chars": [],
        "verdict": "AMAN",
    }

    # Jika input berupa punycode, decode dulu ke unicode
    try:
        if report["is_punycode_input"]:
            report["decoded_unicode"] = idna.decode(domain)
            unicode_form = report["decoded_unicode"]
            report["punycode"] = domain
        else:
            unicode_form = domain
            report["punycode"] = to_punycode(domain)
            report["decoded_unicode"] = domain
    except idna.IDNAError as e:
        unicode_form = domain
        report["decoded_unicode"] = f"[gagal decode: {e}]"

    # Cek tiap karakter: script apa, dan apakah mencurigakan
    name_part = unicode_form.split(".")[0]
    for ch in name_part:
        script = char_script(ch)
        report["scripts_found"].add(script)
        if script not in ("Latin/ASCII",):
            report["suspicious_chars"].append(
                {
                    "char": ch,
                    "unicode_name": unicodedata.name(ch, "UNKNOWN"),
                    "codepoint": f"U+{ord(ch):04X}",
                    "script": script,
                }
            )

    # Verdict: kalau ada campuran Latin + script lain dalam SATU domain -> flag
    non_latin = report["scripts_found"] - {"Latin/ASCII"}
    if non_latin and "Latin/ASCII" in report["scripts_found"]:
        report["verdict"] = "⚠️  SANGAT MENCURIGAKAN (mixed-script homoglyph attack)"
    elif non_latin:
        report["verdict"] = "⚠️  PERLU DICEK (domain non-Latin murni, verifikasi manual)"
    else:
        report["verdict"] = "✅ AMAN (hanya karakter Latin/ASCII)"

    return report


def print_report(report: dict):
    print("-" * 70)
    print(f"Input           : {report['input']}")
    print(f"Bentuk Unicode  : {report['decoded_unicode']}")
    print(f"Bentuk Punycode : {report['punycode']}")
    print(f"Script terdeteksi: {', '.join(sorted(report['scripts_found']))}")
    if report["suspicious_chars"]:
        print("Karakter mencurigakan:")
        for c in report["suspicious_chars"]:
            print(
                f"   -> '{c['char']}' ({c['unicode_name']}, {c['codepoint']}) "
                f"dari script {c['script']}"
            )
    print(f"VERDICT         : {report['verdict']}")
    print("-" * 70)


# ---------------------------------------------------------------------------
# BAGIAN 4: DEMO - 5 domain populer vs varian homograph-nya
# ---------------------------------------------------------------------------
def run_demo():
    """Mode demo: generate & deteksi 5 contoh domain populer."""
    print("=" * 70)
    print(" DEMO: IDN HOMOGRAPH ATTACK - Generate & Deteksi ")
    print(" (untuk tujuan edukasi / security awareness)")
    print(" project by https://github.com/fahmipentest")
    print("=" * 70)

    target_domains = [
        "apple.com",
        "google.com",
        "microsoft.com",
        "paypal.com",
        "amazon.com",
    ]

    print("\n\n### TAHAP 1: Generate contoh domain palsu (homograph) ###\n")
    pairs = []
    for d in target_domains:
        fake = generate_homograph_variant(d)
        puny = to_punycode(fake)
        pairs.append((d, fake, puny))
        print(f"Asli : {d}")
        print(f"Palsu: {fake}   <-- SECARA VISUAL TERLIHAT SAMA")
        print(f"Punycode asli domain palsu: {puny}\n")

    print("\n### TAHAP 2: Jalankan detector pada domain asli vs domain palsu ###\n")
    for original, fake, _ in pairs:
        print(f"\n>>> Mengecek domain ASLI: {original}")
        print_report(analyze_domain(original))

        print(f"\n>>> Mengecek domain PALSU (homograph): {fake}")
        print_report(analyze_domain(fake))


def run_scan(domain: str):
    """Mode scan: analisa satu domain yang diberikan lewat argumen CLI."""
    print("=" * 70)
    print(f" SCANNING DOMAIN: {domain}")
    print(" project by https://github.com/fahmipentest")
    print("=" * 70)
    report = analyze_domain(domain)
    print_report(report)

    # Tampilkan juga contoh varian homograph dari domain ini,
    # supaya user bisa lihat perbandingan visualnya.
    if report["verdict"].startswith("✅"):
        print("\n[i] Domain ini bersih (Latin/ASCII murni).")
        print("[i] Contoh seandainya domain ini dipalsukan dengan teknik homograph:")
        fake = generate_homograph_variant(domain)
        if fake != domain:
            print(f"    -> {fake}  (Punycode: {to_punycode(fake)})")
        else:
            print("    -> (tidak ada karakter yang cocok di tabel homoglyph demo ini)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IDN Homograph Attack - Detector & Demo Generator "
        "(untuk edukasi / security awareness)"
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default=None,
        help="Domain yang mau di-scan, contoh: python3 homograph_detector.py apple.com "
        "(kosongkan untuk menjalankan mode demo 5 domain contoh)",
    )
    args = parser.parse_args()

    if args.domain:
        run_scan(args.domain)
    else:
        run_demo()
