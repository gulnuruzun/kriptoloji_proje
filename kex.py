"""
Anahtar dağıtım yöntemleri: RSA-2048, Diffie-Hellman-2048, ECDH (P-256), ML-KEM-768 (Kyber).

Akış (hepsi için aynı iskelet):
    sunucu: start()            -> sunucu mesajı (açık anahtar / açık değer)
    istemci: respond(mesaj)    -> (istemci mesajı, AES-128 anahtarı, istemci anahtar üretim süresi ms)
    sunucu: finish(mesaj)      -> AES-128 anahtarı
"""
import os
import secrets
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from protocol import derive_key16

METHODS = ("rsa", "dh", "ecc", "kyber")

# RFC 3526, 2048-bit MODP Group (Group 14), g = 2
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_P = int(_P_HEX, 16)
DH_G = 2
_DH_LEN = 256
_CURVE = ec.SECP256R1()


def _dh_keypair():
    """DH anahtar çifti: x (256 bit rastgele üs), y = g^x mod p."""
    x = secrets.randbits(256) | (1 << 255)
    return x, pow(DH_G, x, DH_P)


def _dh_shared(x: int, peer_bytes: bytes) -> bytes:
    y = int.from_bytes(peer_bytes, "big")
    if not 2 <= y <= DH_P - 2:
        raise ValueError("Geçersiz DH açık değeri")
    return pow(y, x, DH_P).to_bytes(_DH_LEN, "big")


def _ms(t0):
    return (time.perf_counter() - t0) * 1000.0


def _kyber():
    try:
        from kyber_py.ml_kem import ML_KEM_768
        return ML_KEM_768
    except ImportError as e:
        raise RuntimeError("Kyber için: pip install kyber-py") from e


class ServerKex:
    def __init__(self, method: str):
        if method not in METHODS:
            raise ValueError(f"Bilinmeyen yöntem: {method}")
        self.method = method
        self.keygen_ms = 0.0
        self._priv = None

    def start(self) -> bytes:
        m, t0 = self.method, time.perf_counter()
        if m == "rsa":
            self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            out = self._priv.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        elif m == "dh":
            x, y = _dh_keypair()
            self._priv = x
            out = y.to_bytes(_DH_LEN, "big")
        elif m == "ecc":
            self._priv = ec.generate_private_key(_CURVE)
            out = self._priv.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        else:
            ek, self._priv = _kyber().keygen()
            out = bytes(ek)
        self.keygen_ms = _ms(t0)
        return out

    def finish(self, client_msg: bytes) -> bytes:
        m = self.method
        if m == "rsa":
            key = self._priv.decrypt(client_msg, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            if len(key) != 16:
                raise ValueError("Geçersiz AES anahtarı uzunluğu")
            return key
        if m == "dh":
            return derive_key16(_dh_shared(self._priv, client_msg), m)
        if m == "ecc":
            peer = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, client_msg)
            return derive_key16(self._priv.exchange(ec.ECDH(), peer), m)
        return derive_key16(bytes(_kyber().decaps(self._priv, client_msg)), m)


class ClientKex:
    def __init__(self, method: str):
        if method not in METHODS:
            raise ValueError(f"Bilinmeyen yöntem: {method}")
        self.method = method
        self.keygen_ms = 0.0

    def respond(self, server_msg: bytes):
        """Dönüş: (istemci mesajı, AES-128 anahtarı)."""
        m = self.method
        if m == "rsa":
            t0 = time.perf_counter()
            key = os.urandom(16)                       # rastgele AES-128 anahtarı
            self.keygen_ms = _ms(t0)
            pub = serialization.load_der_public_key(server_msg)
            ct = pub.encrypt(key, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            return ct, key
        if m == "dh":
            t0 = time.perf_counter()
            x, y = _dh_keypair()
            self.keygen_ms = _ms(t0)
            return y.to_bytes(_DH_LEN, "big"), derive_key16(_dh_shared(x, server_msg), m)
        if m == "ecc":
            t0 = time.perf_counter()
            priv = ec.generate_private_key(_CURVE)
            pt = priv.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            self.keygen_ms = _ms(t0)
            peer = ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, server_msg)
            return pt, derive_key16(priv.exchange(ec.ECDH(), peer), m)
        # Kyber: istemci anahtar üretmez, kapsüller (encapsulate)
        self.keygen_ms = 0.0
        shared, ct = _kyber().encaps(server_msg)
        return bytes(ct), derive_key16(bytes(shared), m)
