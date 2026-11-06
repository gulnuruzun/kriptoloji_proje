"""
Manuel AES-128 ile kütüphane (cryptography/OpenSSL) karşılaştırması.
    python compare_aes.py
"""
import os
import time

from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import aes_manual as m


def lib_ecb(key, data):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()


def lib_cbc(key, iv, data, pad=True):
    if pad:
        p = sympad.PKCS7(128).padder()
        data = p.update(data) + p.finalize()
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def ok(b):
    return "ESLEŞTİ ✔" if b else "FARKLI ✘"


print("=== 1) FIPS-197 Ek-B/C.1 test vektörü (tek blok, ECB, dolgusuz) ===")
key = bytes(range(16))
pt = bytes.fromhex("00112233445566778899aabbccddeeff")
expected = "69c4e0d86a7b0430d8cdb78070b4c55a"
man = m.ecb_encrypt(key, pt)
lib = lib_ecb(key, pt)
print("Girdi          :", pt.hex())
print("Anahtar        :", key.hex())
print("Standart (FIPS):", expected)
print("Manuel         :", man.hex(), ok(man.hex() == expected))
print("Kütüphane      :", lib.hex(), ok(lib.hex() == expected))
print("Manuel çözme   :", m.decrypt_block(man, m.expand_key(key)).hex())

print("\n=== 2) Aynı anahtar/IV ile CBC + PKCS#7 (metin) ===")
iv = bytes(range(100, 116))
text = "Merhaba KTÜ Kriptoloji 2026!".encode("utf-8")
a, b = m.cbc_encrypt(key, iv, text), lib_cbc(key, iv, text)
print("Düz metin      :", text, f"({len(text)} bayt)")
print("Manuel CBC     :", a.hex())
print("Kütüphane CBC  :", b.hex(), ok(a == b))
print("Manuel çözme   :", m.cbc_decrypt(key, iv, a))

print("\n=== 3) Rastgele veriyle 200 deneme (farklı uzunluk, anahtar, IV) ===")
bad = 0
for _ in range(200):
    k, v, d = os.urandom(16), os.urandom(16), os.urandom(os.urandom(1)[0])
    if m.cbc_encrypt(k, v, d) != lib_cbc(k, v, d) or m.cbc_decrypt(k, v, lib_cbc(k, v, d)) != d:
        bad += 1
print("Uyuşmayan deneme sayısı:", bad, ok(bad == 0))

print("\n=== 4) Farkların nedenleri (aynı girdi, farklı yapılandırma) ===")
blk = b"A" * 32                                      # tam 2 blok
print("a) Padding: 32 baytlık girdi -> CBC+PKCS7 çıktısı", len(m.cbc_encrypt(key, iv, blk)),
      "bayt (tam dolgu bloğu eklenir); dolgusuz ECB:", len(m.ecb_encrypt(key, blk)), "bayt")
print("b) Mod: aynı 16B blok iki kez ->  ECB blokları",
      "AYNI" if (lambda c: c[:16] == c[16:])(m.ecb_encrypt(key, b"B" * 32)) else "FARKLI",
      "| CBC blokları",
      "AYNI" if (lambda c: c[:16] == c[16:32])(m.cbc_encrypt(key, iv, b"B" * 32)) else "FARKLI")
print("c) IV: rastgele IV ile aynı metin iki kez şifrelenince çıktılar",
      "AYNI" if lib_cbc(key, os.urandom(16), text) == lib_cbc(key, os.urandom(16), text) else "FARKLI")
g = AESGCM(key).encrypt(os.urandom(12), text, None)
print(f"d) GCM: aynı metin -> {len(g)} bayt (metin {len(text)} + 16B kimlik doğrulama etiketi, dolgu yok)")

print("\n=== 5) Hız (64 KB veri, CBC) ===")
d = os.urandom(64 * 1024)
t = time.perf_counter(); m.cbc_encrypt(key, iv, d); tm = time.perf_counter() - t
t = time.perf_counter(); lib_cbc(key, iv, d); tl = time.perf_counter() - t
print(f"Manuel: {tm*1000:.1f} ms | Kütüphane: {tl*1000:.3f} ms | oran ~{tm/tl:.0f}x")
