# 🔍 IDN Homograph Attack Detector

Script Python untuk mendeteksi dan mendemonstrasikan **IDN Homograph Attack** — teknik phishing di mana domain palsu dibuat terlihat 100% identik dengan domain asli menggunakan karakter Unicode dari script lain (Cyrillic, Greek, dll) yang bentuknya mirip huruf Latin.

Project ini **murni untuk tujuan edukasi dan defensive security** — tidak mendaftarkan domain apapun, tidak membuat halaman phishing, dan tidak melakukan request ke domain manapun. Cocok untuk security awareness training, threat monitoring, dan bahan belajar pentest.

> project by [@fahmipentest](https://github.com/fahmipentest)

## 🎯 Apa itu IDN Homograph Attack?

Berbeda dari typosquatting biasa (`gooogle.com`), homograph attack mengganti karakter Latin dengan karakter Unicode lain yang **secara visual identik**:

```
apple.com   →   аpple.com     (huruf 'a' diganti Cyrillic 'а' U+0430)
```

Browser menerjemahkan domain Unicode ini ke bentuk **Punycode** (`xn--...`) di belakang layar — dan di sinilah domain palsu terbongkar.

## ✨ Fitur

- **Generator**: buat contoh domain homograph dari domain apapun (untuk demo/training)
- **Detector**: analisa domain — decode Punycode, deteksi mixed-script, flag karakter mencurigakan
- **CLI**: scan domain langsung dari terminal
- **Library**: bisa di-import ke script Python lain

## 📦 Instalasi

```bash
git clone https://github.com/fahmipentest/idn-homograph-detector.git
cd idn-homograph-detector
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🚀 Cara Pakai

**Scan satu domain:**
```bash
python3 homograph_detector.py apple.com
python3 homograph_detector.py "рaypal.com"        # domain Unicode
python3 homograph_detector.py xn--aypal-uye.com   # domain Punycode
```

**Mode demo (5 contoh domain populer):**
```bash
python3 homograph_detector.py
```

**Sebagai library:**
```python
from homograph_detector import analyze_domain, print_report

report = analyze_domain("рaypal.com")
print_report(report)
```

## 📸 Contoh Output

```
======================================================================
 SCANNING DOMAIN: рaypal.com
 project by https://github.com/fahmipentest
======================================================================
----------------------------------------------------------------------
Input           : рaypal.com
Bentuk Unicode  : рaypal.com
Bentuk Punycode : xn--aypal-uye.com
Script terdeteksi: Cyrillic, Latin/ASCII
Karakter mencurigakan:
   -> 'р' (CYRILLIC SMALL LETTER ER, U+0440) dari script Cyrillic
VERDICT         : ⚠️  SANGAT MENCURIGAKAN (mixed-script homoglyph attack)
----------------------------------------------------------------------
```

## 🛡️ Use Case

- **Security Awareness Training**: tunjukkan ke tim/klien betapa miripnya domain phishing
- **Email/Link Triage**: cek cepat domain mencurigakan dari laporan phishing
- **Brand Monitoring**: kombinasikan dengan [dnstwist](https://github.com/elceef/dnstwist) untuk cek domain variasi brand yang sudah terdaftar
- **Pentest Reporting**: bukti teknis (Punycode) untuk laporan social engineering assessment

## ⚠️ Disclaimer

Tool ini dibuat untuk tujuan **edukasi dan defensive security** saja. Penggunaan untuk membuat/mendaftarkan domain phishing sungguhan di luar scope engagement resmi (dengan izin tertulis) adalah ilegal. Gunakan secara bertanggung jawab.

## 📄 Lisensi

MIT License — lihat file [LICENSE](LICENSE)

---

Dibuat dengan ❤️ untuk komunitas security Indonesia oleh [@fahmipentest](https://github.com/fahmipentest)
