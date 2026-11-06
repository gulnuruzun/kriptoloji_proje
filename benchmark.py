"""
Anahtar dağıtım yöntemleri ölçümü (gerçek ağ üzerinden, çalışan sunucuya karşı).

    python benchmark.py --host 192.168.1.10 [--runs 10]

Ölçülenler (10 ölçümün ortalaması):
  1) Anahtar üretme süresi  = istemci + sunucu asimetrik anahtar üretimi (ms)
     (RSA: sunucu RSA-2048 çifti üretir, istemci rastgele AES anahtarı üretir;
      DH/ECC: iki taraf da çift üretir; Kyber: sunucu ML-KEM-768 çifti üretir)
  2) Anahtar değişimi süresi = hello'dan ACK'ye toplam süre - anahtar üretme süreleri (ms)
     (ağ gecikmesi + şifreleme/kapsülleme/türetme + doğrulama)
  3) Ağdaki paket boyutu = el sıkışmada gönderilen + alınan uygulama bayt toplamı
     (TCP payload; Wireshark'ta aynı akışın TCP payload toplamıyla karşılaştırılabilir)
"""
import argparse
import csv
import statistics as st

from client import SecureClient
from kex import METHODS
from protocol import DEFAULT_PORT

NAMES = {"rsa": "RSA-2048", "dh": "Diffie-Hellman-2048", "ecc": "ECC (ECDH P-256)",
         "kyber": "Kyber (ML-KEM-768)"}


def measure(host, port, method, runs):
    rows = []
    for i in range(runs + 1):                      # ilk tur ısınma, atılır
        c = SecureClient(host, port, f"bench-{method}", "secure", method, role="bench")
        m = c.connect()
        c.close()
        if i == 0:
            continue
        kg = m["client_keygen_ms"] + m["server_keygen_ms"]
        rows.append((m["client_keygen_ms"], m["server_keygen_ms"], kg,
                     max(m["total_ms"] - kg, 0.0), m["bytes_sent"], m["bytes_received"]))
    return [st.mean(col) for col in zip(*rows)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--runs", type=int, default=10)
    a = ap.parse_args()

    results = []
    for m in METHODS:
        try:
            r = measure(a.host, a.port, m, a.runs)
        except Exception as e:
            print(f"{NAMES[m]}: atlandı ({e})")
            continue
        results.append((NAMES[m], *r))

    head = ["Yöntem", "Üretim-istemci (ms)", "Üretim-sunucu (ms)", "Üretim-toplam (ms)",
            "Değişim (ms)", "Giden (B)", "Gelen (B)", "Toplam paket (B)"]
    print(f"\n{a.runs} ölçümün ortalaması\n")
    print("| " + " | ".join(head) + " |")
    print("|" + "---|" * len(head))
    out = []
    for n, ckg, skg, kg, ex, tx, rx in results:
        row = [n, f"{ckg:.2f}", f"{skg:.2f}", f"{kg:.2f}", f"{ex:.2f}", f"{tx:.0f}", f"{rx:.0f}", f"{tx + rx:.0f}"]
        out.append(row)
        print("| " + " | ".join(row) + " |")
    with open("benchmark_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(head)
        w.writerows(out)
    print("\nbenchmark_results.csv yazıldı.")


if __name__ == "__main__":
    main()
