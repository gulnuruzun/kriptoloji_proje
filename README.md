# Güvenli Haberleşme Projesi (Sunucu – İstemci – İstemci)

Python 3.10+ ile yazıldı. Sunucu iki istemci arasında metin ve PDF yönlendirir.
Güvensiz modda veri düz gider; güvenli modda AES-128-CBC + HMAC-SHA256 ile şifrelenir.
AES anahtarı RSA-2048, Diffie-Hellman-2048, ECDH (P-256) veya ML-KEM-768 (Kyber) ile paylaşılır.

## Dosyalar
| Dosya | Görev |
|---|---|
| `server.py` | Sunucu (her istemciyle ayrı anahtar, çöz → göster/kaydet → yeniden şifrele → ilet) |
| `client.py` | İstemci (GUI; `--cli` ile terminal) |
| `kex.py` | RSA / DH / ECC / Kyber anahtar dağıtımı |
| `protocol.py` | Çerçeveleme, bayt sayacı, AES oturumu |
| `aes_manual.py` | Kütüphanesiz AES-128 (S-box, round'lar, CBC, PKCS#7) |
| `compare_aes.py` | Manuel AES ↔ kütüphane karşılaştırması |
| `benchmark.py` | Dört yöntemin ölçüm tablosu (10 ölçüm ortalaması) |

## Kurulum (her bilgisayarda)
```
pip install -r requirements.txt
```
GUI için tkinter gerekir (Windows/macOS Python ile gelir; Linux: `sudo apt install python3-tk`).

## Çalıştırma
**Bilgisayar 1 (sunucu):** önce IP'ni öğren (`ipconfig` / `ip a`), güvenlik duvarında TCP 9009'a izin ver.
```
python server.py
```
**Bilgisayar 2 (iki istemci, iki ayrı terminal):**
```
python client.py            # GUI: IP, ad, mod, yöntem seç -> Bağlan
python client.py
```
Terminal sürümü: `python client.py --cli --host <SUNUCU_IP> --name Ali --mode secure --method kyber`
(`/pdf dosya.pdf` PDF gönderir, `/quit` çıkar.) İki istemci farklı adlar kullanmalı.

Alınan PDF'ler: istemcide `received_files/`, sunucuda `server_files/`.

## Ölçüm (Bilgisayar 2'den)
```
python benchmark.py --host <SUNUCU_IP> --runs 10
python compare_aes.py
```
`benchmark_results.csv` oluşur.

## Wireshark
- Filtre: `tcp.port == 9009`
- Güvensiz mod: sağ tık → Follow → TCP Stream → metin ve `%PDF` açıkça görünür.
- Güvenli mod: aynı akışta yalnızca `{"type":"enc"}` başlığı ve rastgele bayt görünür.
- Yakalamayı hem sunucu hem istemci bilgisayarında yapıp `.pcapng` kaydet.
