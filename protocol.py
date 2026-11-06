"""
Ortak protokol katmanı: çerçeveleme (framing), bayt sayacı ve AES oturum şifreleyicisi.

Çerçeve biçimi (TCP üzerinde):
    | header_len (4B) | payload_len (4B) | header (JSON, UTF-8) | payload (ham bayt) |

Güvensiz modda çerçeve doğrudan gönderilir (Wireshark'ta okunur).
Güvenli modda asıl çerçeve (başlık dahil) AES-128-CBC + HMAC ile şifrelenir ve
{"type": "enc"} başlıklı bir dış çerçevenin payload'ı olarak gönderilir.
Böylece dosya adı, gönderen adı gibi meta veriler de gizlenir.
"""
import hashlib
import hmac
import json
import os
import struct
import threading

from cryptography.hazmat.primitives import hashes, padding as sympad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import aes_manual

DEFAULT_PORT = 9009
CHUNK_SIZE = 16 * 1024
MAX_HEADER = 64 * 1024
MAX_PAYLOAD = 8 * 1024 * 1024
MACLEN = 32


# ---------------------------------------------------------------- çerçeveleme
def encode_frame(header: dict, payload: bytes = b"") -> bytes:
    h = json.dumps(header, ensure_ascii=False).encode("utf-8")
    return struct.pack(">II", len(h), len(payload)) + h + payload


def decode_frame(data: bytes):
    hl, pl = struct.unpack(">II", data[:8])
    if hl > MAX_HEADER or pl > MAX_PAYLOAD or len(data) != 8 + hl + pl:
        raise ValueError("Bozuk çerçeve")
    return json.loads(data[8:8 + hl].decode("utf-8")), data[8 + hl:]


class Conn:
    """Soket sarmalayıcı: çerçeve gönder/al + gönderilen/alınan bayt sayacı."""

    def __init__(self, sock):
        self.sock = sock
        self.sent = 0
        self.received = 0
        self._wlock = threading.Lock()

    def send_raw(self, data: bytes):
        with self._wlock:
            self.sock.sendall(data)
            self.sent += len(data)

    def send_frame(self, header: dict, payload: bytes = b""):
        self.send_raw(encode_frame(header, payload))

    def _read(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Bağlantı kapandı")
            buf += chunk
        return bytes(buf)

    def recv_frame(self):
        hl, pl = struct.unpack(">II", self._read(8))
        if hl > MAX_HEADER or pl > MAX_PAYLOAD:
            raise ValueError("Çerçeve boyutu sınırı aşıldı")
        body = self._read(hl + pl)
        self.received += 8 + hl + pl
        return json.loads(body[:hl].decode("utf-8")), body[hl:]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------------------ AES oturumu
def derive_key16(shared_secret: bytes, method: str) -> bytes:
    """DH / ECDH / ML-KEM ortak sırrından 16 baytlık AES anahtarı türetir."""
    return HKDF(algorithm=hashes.SHA256(), length=16, salt=None,
                info=b"securecomm-aes128-" + method.encode()).derive(shared_secret)


class SessionCipher:
    """AES-128-CBC (PKCS#7) + HMAC-SHA256 (encrypt-then-MAC).

    Çıktı: IV(16) || şifreli metin || etiket(32)
    backend: 'lib' -> cryptography kütüphanesi, 'manual' -> aes_manual.py
    İki arka uç birebir aynı çıktıyı üretir (IV aynıysa) ve birbiriyle uyumludur.
    """

    def __init__(self, key16: bytes, backend: str = "lib"):
        if len(key16) != 16:
            raise ValueError("AES-128 anahtarı 16 bayt olmalı")
        self.key = key16
        self.backend = backend
        self.mac_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                            info=b"securecomm-hmac").derive(key16)

    def _cbc_enc(self, iv, data):
        if self.backend == "manual":
            return aes_manual.cbc_encrypt(self.key, iv, data)
        padder = sympad.PKCS7(128).padder()
        enc = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        return enc.update(padder.update(data) + padder.finalize()) + enc.finalize()

    def _cbc_dec(self, iv, data):
        if self.backend == "manual":
            return aes_manual.cbc_decrypt(self.key, iv, data)
        dec = Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
        unpadder = sympad.PKCS7(128).unpadder()
        return unpadder.update(dec.update(data) + dec.finalize()) + unpadder.finalize()

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(16)
        body = iv + self._cbc_enc(iv, plaintext)
        return body + hmac.new(self.mac_key, body, hashlib.sha256).digest()

    def decrypt(self, blob: bytes) -> bytes:
        if len(blob) < 16 + 16 + MACLEN:
            raise ValueError("Şifreli veri çok kısa")
        body, tag = blob[:-MACLEN], blob[-MACLEN:]
        if not hmac.compare_digest(tag, hmac.new(self.mac_key, body, hashlib.sha256).digest()):
            raise ValueError("HMAC doğrulaması başarısız (veri değiştirilmiş olabilir)")
        return self._cbc_dec(body[:16], body[16:])
