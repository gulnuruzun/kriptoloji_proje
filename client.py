"""
İstemci (GUI + terminal).

GUI:       python client.py
Terminal:  python client.py --cli --host 192.168.1.10 --name Ali --mode secure --method kyber
           (terminalde: yazdığın satır metin olarak gider; '/pdf yol/dosya.pdf' PDF gönderir; '/quit' çıkar)
"""
import argparse
import hashlib
import os
import queue
import socket
import sys
import threading
import time
import uuid

from kex import METHODS, ClientKex
from protocol import CHUNK_SIZE, DEFAULT_PORT, Conn, SessionCipher, decode_frame, encode_frame

RECV_DIR = "received_files"


class SecureClient:
    def __init__(self, host, port, name, mode="secure", method="ecc",
                 aes="lib", role="chat", on_event=None, recv_dir=RECV_DIR):
        self.host, self.port, self.name = host, port, name
        self.mode, self.method, self.aes, self.role = mode, method, aes, role
        self.on_event = on_event or (lambda kind, data: None)
        self.recv_dir = recv_dir
        self.conn = None
        self.cipher = None
        self.metrics = {}
        self._files = {}
        self._running = False

    # ------------------------------------------------------------ bağlantı
    def connect(self):
        sock = socket.create_connection((self.host, self.port), timeout=15)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(None)
        self.conn = Conn(sock)
        hello = {"type": "hello", "name": self.name, "mode": self.mode,
                 "method": self.method if self.mode == "secure" else None, "role": self.role}
        if self.mode == "insecure":
            self.conn.send_frame(hello)
            self.conn.recv_frame()
            self.metrics = {}
        else:
            self._secure_handshake(hello)
        self._running = True
        if self.role == "chat":
            threading.Thread(target=self._recv_loop, daemon=True).start()
        return self.metrics

    def _secure_handshake(self, hello):
        c = self.conn
        t0 = time.perf_counter()
        c.send_frame(hello)
        h, server_msg = c.recv_frame()
        if h.get("type") != "kex_server":
            raise RuntimeError(f"Beklenmeyen yanıt: {h}")
        server_keygen = float(h.get("server_keygen_ms", 0.0))
        kex = ClientKex(self.method)
        client_msg, key = kex.respond(server_msg)
        self.cipher = SessionCipher(key, self.aes)
        c.send_frame({"type": "kex_client"}, client_msg)
        h, blob = c.recv_frame()
        if h.get("type") != "kex_ack" or self.cipher.decrypt(blob) != b"ACK-SERVER":
            raise RuntimeError("Sunucu ACK doğrulaması başarısız")
        c.send_frame({"type": "kex_done"}, self.cipher.encrypt(b"ACK-CLIENT"))
        total = (time.perf_counter() - t0) * 1000.0
        self.metrics = {
            "total_ms": total,
            "client_keygen_ms": kex.keygen_ms,
            "server_keygen_ms": server_keygen,
            "bytes_sent": c.sent,
            "bytes_received": c.received,
        }

    # ------------------------------------------------------------ gönderme
    def _send_inner(self, header, payload=b""):
        if self.cipher:
            self.conn.send_frame({"type": "enc"}, self.cipher.encrypt(encode_frame(header, payload)))
        else:
            self.conn.send_frame(header, payload)

    def send_text(self, text: str):
        self._send_inner({"type": "text"}, text.encode("utf-8"))

    def send_pdf(self, path: str):
        if not path.lower().endswith(".pdf"):
            raise ValueError("Sadece PDF dosyası gönderilebilir")
        data = open(path, "rb").read()
        fid, sha = uuid.uuid4().hex[:8], hashlib.sha256(data).hexdigest()
        self._send_inner({"type": "file_start", "id": fid, "filename": os.path.basename(path),
                          "size": len(data), "sha256": sha})
        for seq, i in enumerate(range(0, len(data), CHUNK_SIZE)):
            self._send_inner({"type": "file_chunk", "id": fid, "seq": seq}, data[i:i + CHUNK_SIZE])
        self._send_inner({"type": "file_end", "id": fid, "sha256": sha})
        return len(data)

    def close(self):
        self._running = False
        if self.conn:
            try:
                self._send_inner({"type": "bye"})
            except OSError:
                pass
            self.conn.close()

    # -------------------------------------------------------------- alma
    def _recv_loop(self):
        try:
            while self._running:
                h, p = self.conn.recv_frame()
                if h.get("type") == "enc":
                    h, p = decode_frame(self.cipher.decrypt(p))
                self._handle(h, p)
        except Exception as e:
            if self._running:
                self.on_event("error", f"Bağlantı koptu: {e}")

    def _handle(self, h, p):
        t = h.get("type")
        if t == "text":
            self.on_event("text", (h.get("from"), p.decode("utf-8", "replace")))
        elif t == "info":
            self.on_event("info", h.get("msg"))
        elif t == "file_start":
            os.makedirs(self.recv_dir, exist_ok=True)
            path = os.path.join(self.recv_dir, f"{h['from']}_{os.path.basename(h['filename'])}")
            self._files[h["id"]] = [open(path, "wb"), path, hashlib.sha256()]
            self.on_event("info", f"{h['from']} PDF gönderiyor: {h['filename']} ({h['size']} bayt)")
        elif t == "file_chunk":
            f = self._files.get(h["id"])
            if f:
                f[0].write(p); f[2].update(p)
        elif t == "file_end":
            f = self._files.pop(h["id"], None)
            if f:
                f[0].close()
                ok = f[2].hexdigest() == h.get("sha256")
                self.on_event("file", (h.get("from"), f[1], ok))


# ---------------------------------------------------------------- terminal
def run_cli(a):
    c = SecureClient(a.host, a.port, a.name, a.mode, a.method, a.aes,
                     on_event=lambda k, d: print(f"\n<< {k}: {d}", flush=True))
    m = c.connect()
    print(f"Bağlandı. mod={a.mode} yöntem={a.method if a.mode == 'secure' else '-'}")
    if m:
        print("Anahtar değişimi:", {k: round(v, 2) for k, v in m.items()})
    print("Metin yaz + Enter | /pdf dosya.pdf | /quit")
    for line in sys.stdin:
        line = line.rstrip("\n")
        if line == "/quit":
            break
        if line.startswith("/pdf "):
            try:
                print("PDF gönderildi,", c.send_pdf(line[5:].strip()), "bayt")
            except Exception as e:
                print("Hata:", e)
        elif line:
            c.send_text(line)
    c.close()


# --------------------------------------------------------------------- GUI
def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    root = tk.Tk()
    root.title("Güvenli Haberleşme - İstemci")
    ev = queue.Queue()
    state = {"client": None}

    top = ttk.Frame(root, padding=6)
    top.pack(fill="x")
    vars_ = {k: tk.StringVar(value=v) for k, v in
             dict(host="127.0.0.1", port=str(DEFAULT_PORT), name="Istemci1",
                  mode="secure", method="ecc", aes="lib").items()}
    labels = [("Sunucu IP", "host", None), ("Port", "port", None), ("Ad", "name", None),
              ("Mod", "mode", ("secure", "insecure")),
              ("Anahtar yöntemi", "method", METHODS), ("AES", "aes", ("lib", "manual"))]
    for i, (lbl, key, vals) in enumerate(labels):
        ttk.Label(top, text=lbl).grid(row=0, column=i, sticky="w", padx=3)
        w = ttk.Combobox(top, textvariable=vars_[key], values=vals, width=10, state="readonly") \
            if vals else ttk.Entry(top, textvariable=vars_[key], width=14 if key == "host" else 10)
        w.grid(row=1, column=i, padx=3)
    log = scrolledtext.ScrolledText(root, height=20, width=90, state="disabled")
    log.pack(fill="both", expand=True, padx=6, pady=4)

    def write(msg):
        log.configure(state="normal")
        log.insert("end", time.strftime("[%H:%M:%S] ") + msg + "\n")
        log.see("end")
        log.configure(state="disabled")

    def connect():
        try:
            c = SecureClient(vars_["host"].get(), int(vars_["port"].get()), vars_["name"].get(),
                             vars_["mode"].get(), vars_["method"].get(), vars_["aes"].get(),
                             on_event=lambda k, d: ev.put((k, d)))
            m = c.connect()
        except Exception as e:
            messagebox.showerror("Bağlantı hatası", str(e))
            return
        state["client"] = c
        btn_connect.configure(state="disabled")
        write(f"Bağlandı ({vars_['mode'].get()}, {vars_['method'].get() if m else '-'})")
        if m:
            write(f"Anahtar değişimi: toplam {m['total_ms']:.1f} ms, "
                  f"{m['bytes_sent'] + m['bytes_received']} bayt")

    btn_connect = ttk.Button(top, text="Bağlan", command=connect)
    btn_connect.grid(row=1, column=len(labels), padx=6)

    bottom = ttk.Frame(root, padding=6)
    bottom.pack(fill="x")
    entry = ttk.Entry(bottom)
    entry.pack(side="left", fill="x", expand=True)

    def send_text(_=None):
        c, t = state["client"], entry.get().strip()
        if c and t:
            c.send_text(t)
            write(f"Ben: {t}")
            entry.delete(0, "end")

    def send_pdf():
        c = state["client"]
        if not c:
            return
        path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if path:
            threading.Thread(target=lambda: (c.send_pdf(path), ev.put(("info", f"PDF gönderildi: {os.path.basename(path)}"))),
                             daemon=True).start()

    entry.bind("<Return>", send_text)
    ttk.Button(bottom, text="Gönder", command=send_text).pack(side="left", padx=4)
    ttk.Button(bottom, text="PDF Seç ve Gönder", command=send_pdf).pack(side="left")

    def poll():
        while not ev.empty():
            k, d = ev.get()
            if k == "text":
                write(f"{d[0]}: {d[1]}")
            elif k == "file":
                write(f"PDF alındı ({d[0]}): {d[1]}  SHA-256 {'DOĞRU' if d[2] else 'HATALI'}")
            else:
                write(str(d))
        root.after(150, poll)

    poll()
    root.protocol("WM_DELETE_WINDOW", lambda: (state["client"] and state["client"].close(), root.destroy()))
    root.mainloop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--name", default="Istemci1")
    ap.add_argument("--mode", choices=("secure", "insecure"), default="secure")
    ap.add_argument("--method", choices=METHODS, default="ecc")
    ap.add_argument("--aes", choices=("lib", "manual"), default="lib")
    a = ap.parse_args()
    run_cli(a) if a.cli else run_gui()


if __name__ == "__main__":
    main()
