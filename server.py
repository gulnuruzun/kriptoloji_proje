"""
Sunucu: iki istemci arasında mesaj/PDF yönlendirir.

Çalıştırma:  python server.py [--host 0.0.0.0] [--port 9009] [--aes lib|manual]

- Her istemci hello ile mod (secure/insecure) ve anahtar yöntemini bildirir.
- Güvenli modda sunucu her istemciyle AYRI AES-128 anahtarı paylaşır.
- Gelen veri o istemcinin anahtarıyla çözülür, ekrana yazılır / dosya kaydedilir,
  sonra alıcının anahtarıyla yeniden şifrelenip iletilir.
"""
import argparse
import hashlib
import os
import socket
import threading
import time

from kex import METHODS, ServerKex
from protocol import DEFAULT_PORT, Conn, SessionCipher, decode_frame, encode_frame

SAVE_DIR = "server_files"
lock = threading.Lock()
clients = {}          # ad -> Session


def log(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


class Session:
    def __init__(self, conn, name, mode, method, cipher):
        self.conn, self.name, self.mode, self.method, self.cipher = conn, name, mode, method, cipher
        self.files = {}   # file_id -> (dosya nesnesi, yol, hash)

    def send_inner(self, header, payload=b""):
        """Çerçeveyi bu istemcinin moduna göre (düz / şifreli) gönderir."""
        if self.cipher:
            self.conn.send_frame({"type": "enc"}, self.cipher.encrypt(encode_frame(header, payload)))
        else:
            self.conn.send_frame(header, payload)


def handshake(conn, aes_backend):
    hello, _ = conn.recv_frame()
    if hello.get("type") != "hello":
        raise ValueError("İlk mesaj hello olmalı")
    name = str(hello.get("name", "?"))[:32]
    mode = hello.get("mode", "insecure")
    method = hello.get("method")
    role = hello.get("role", "chat")
    if mode == "insecure":
        conn.send_frame({"type": "hello_ok", "mode": "insecure"})
        return name, mode, None, None, role

    if method not in METHODS:
        raise ValueError(f"Bilinmeyen yöntem: {method}")
    kex = ServerKex(method)
    server_msg = kex.start()
    conn.send_frame({"type": "kex_server", "method": method,
                     "server_keygen_ms": kex.keygen_ms}, server_msg)
    h, client_msg = conn.recv_frame()
    if h.get("type") != "kex_client":
        raise ValueError("kex_client bekleniyordu")
    cipher = SessionCipher(kex.finish(client_msg), aes_backend)
    conn.send_frame({"type": "kex_ack"}, cipher.encrypt(b"ACK-SERVER"))
    h, blob = conn.recv_frame()
    if h.get("type") != "kex_done" or cipher.decrypt(blob) != b"ACK-CLIENT":
        raise ValueError("Anahtar doğrulaması başarısız")
    return name, mode, method, cipher, role


def forward(sender, header, payload=b""):
    with lock:
        targets = [c for c in clients.values() if c is not sender]
    if not targets:
        sender.send_inner({"type": "info", "msg": "Karşı istemci bağlı değil, mesaj iletilemedi."})
        return
    for t in targets:
        try:
            t.send_inner(header, payload)
        except OSError:
            pass


def handle_message(s, h, p):
    t = h.get("type")
    if t == "text":
        text = p.decode("utf-8", "replace")
        log(f"METİN  {s.name} -> : {text}")
        forward(s, {"type": "text", "from": s.name}, p)
    elif t == "file_start":
        fid = h["id"]
        fname = os.path.basename(h["filename"]) or "dosya.pdf"
        os.makedirs(SAVE_DIR, exist_ok=True)
        path = os.path.join(SAVE_DIR, f"{s.name}_{fname}")
        s.files[fid] = [open(path, "wb"), path, hashlib.sha256(), 0]
        log(f"DOSYA  {s.name}: '{fname}' ({h.get('size')} bayt) alınmaya başlandı")
        forward(s, {"type": "file_start", "from": s.name, "id": fid,
                    "filename": fname, "size": h.get("size"), "sha256": h.get("sha256")})
    elif t == "file_chunk":
        f = s.files.get(h["id"])
        if f:
            f[0].write(p); f[2].update(p); f[3] += len(p)
        forward(s, {"type": "file_chunk", "from": s.name, "id": h["id"], "seq": h.get("seq")}, p)
    elif t == "file_end":
        f = s.files.pop(h["id"], None)
        if f:
            f[0].close()
            ok = f[2].hexdigest() == h.get("sha256")
            log(f"DOSYA  kaydedildi: {f[1]} ({f[3]} bayt) SHA-256 {'DOĞRU' if ok else 'HATALI'}")
        forward(s, {"type": "file_end", "from": s.name, "id": h["id"], "sha256": h.get("sha256")})
    elif t == "bye":
        raise ConnectionError("istemci ayrıldı")


def serve_client(sock, addr, aes_backend):
    conn = Conn(sock)
    s = None
    try:
        name, mode, method, cipher, role = handshake(conn, aes_backend)
        s = Session(conn, name, mode, method, cipher)
        if role == "chat":
            with lock:
                clients[name] = s
            log(f"BAĞLANDI {name} {addr[0]}:{addr[1]} mod={mode} yöntem={method or '-'}")
        else:
            log(f"ÖLÇÜM    {addr[0]} yöntem={method} (el sıkışma {conn.sent + conn.received} bayt)")
        while True:
            h, p = conn.recv_frame()
            if h.get("type") == "enc":
                if not cipher:
                    raise ValueError("Güvensiz oturumda şifreli çerçeve")
                h, p = decode_frame(cipher.decrypt(p))
            handle_message(s, h, p)
    except (ConnectionError, OSError):
        pass
    except Exception as e:                       # bozuk/oynanmış veri vb.
        log(f"HATA {addr[0]}: {e}")
    finally:
        if s:
            for f in s.files.values():
                f[0].close()
            with lock:
                if clients.get(s.name) is s:
                    del clients[s.name]
            if s.name:
                log(f"AYRILDI {s.name}")
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--aes", choices=("lib", "manual"), default="lib",
                    help="AES arka ucu: lib (cryptography) veya manual (aes_manual.py)")
    a = ap.parse_args()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.port))
    srv.listen(8)
    log(f"Sunucu dinliyor {a.host}:{a.port}  (AES arka ucu: {a.aes})")
    while True:
        c, addr = srv.accept()
        threading.Thread(target=serve_client, args=(c, addr, a.aes), daemon=True).start()


if __name__ == "__main__":
    main()
