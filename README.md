# tlsscan

`ip:port` listesindeki her hedefin şifreleme yapılandırmasını çıkaran, zayıf olanları işaretleyen ve isteğe bağlı olarak bulguları ikinci bir araçla (sslscan) doğrulayan tarama script'i. Sonuçlar CSV (ve istenirse JSON) olarak yazılır.

İki tarama motoru vardır:

| Motor | Gereksinim | Ne zaman |
|---|---|---|
| `nmap` | nmap kurulu olmalı | Kali/Linux; nmap NSE script'leri kullanılır |
| `python` | Sadece Python 3.7+ (ek paket yok) | **nmap'in olmadığı / kurulum izni olmayan makineler (ör. Windows)** |

Varsayılan `--engine auto`: nmap varsa nmap, yoksa Python motoru kullanılır. İki motor da aynı CSV formatında çıktı üretir.

## Ne yapıyor?

### nmap motoru

Her hedef için tek bir nmap çalıştırılır (`-sV` ile servis tespiti + aşağıdaki NSE script'leri). Port hangi servisse ilgili script sonuç döner:

| Servis | NSE script | Çıkarılan bilgi |
|---|---|---|
| TLS/SSL (HTTPS, STARTTLS'li SMTP/IMAP/POP3/FTP/LDAP/…) | `ssl-enum-ciphers` | Desteklenen sürümler (SSLv3 → TLS 1.3), her sürümdeki cipher'lar, A–F notu, kex bilgisi, cipher tercih sırası, sıkıştırma, uyarılar (SWEET32 vb.) |
| | `ssl-cert` | Subject, issuer, SAN, anahtar tipi/uzunluğu, imza algoritması, geçerlilik tarihleri |
| | `ssl-dh-params` | Zayıf DH grubu, Logjam, anonim DH, safe-prime olmayan grup |
| SSH | `ssh2-enum-algos` | Kex, host key, şifreleme, MAC ve sıkıştırma algoritmaları |
| RDP | `rdp-enum-encryption` | RDP güvenlik katmanı (Native RDP / TLS / CredSSP) ve şifreleme seviyesi |

Zayıf olarak işaretlenen (`weak=YES`) durumlar:

- **TLS:** SSLv2/v3 ve TLS 1.0/1.1; NULL, EXPORT, anon, RC4, DES/3DES, MD5 içeren cipher'lar; nmap notu A'dan düşük olanlar; TLS sıkıştırması; nmap uyarıları
- **Sertifika:** RSA/DSA anahtarı < 2048 bit, EC anahtarı < 256 bit; MD5/SHA1 imza; süresi dolmuş; self-signed
- **DH:** `ssl-dh-params` tarafından VULNERABLE bulunan her kontrol
- **SSH:** CBC modlu şifreler, arcfour, 3des, blowfish, cast128; hmac-md5, `*-96` MAC'ler, umac-64; `diffie-hellman-group1-*`, sha1 tabanlı DH; ssh-dss; `none`
- **RDP:** 40/56-bit şifreleme

### Python motoru (`pyscan.py`)

Sadece Python standart kütüphanesi (`socket`, `ssl`, `struct`) kullanılır; hiçbir şey kurulmaz.

- **Servis tespiti:** Sunucunun ilk gönderdiği banner'a göre SSH, SMTP/FTP/IMAP/POP3 (STARTTLS) ayırt edilir; banner yoksa doğrudan TLS, olmazsa RDP denenir.
- **TLS sürüm ve cipher'lar:** ClientHello paketi elle oluşturulur ve sunucunun ServerHello yanıtı okunur (nmap'in `ssl-enum-ciphers` script'iyle aynı yöntem). Böylece sonuç **yerel OpenSSL'e bağlı değildir**: Windows'taki Python'un OpenSSL'i SSLv3, RC4, EXPORT, NULL gibi eski cipher'ları desteklemese de bunların sunucuda açık olup olmadığı tespit edilir. Kabul edilen cipher'lar eleme yöntemiyle bulunur (liste teklif edilir, sunucunun seçtiği çıkarılır, sunucu reddedene kadar tekrarlanır). Sunucu tercih sırası (server/client) da belirlenir. SSLv3, TLS 1.0, 1.1, 1.2 ve 1.3 taranır.
- **Kex:** ServerKeyExchange mesajından ECDHE eğrisi ve DHE modulus uzunluğu okunur (`kex=x25519`, `kex=dh 1024`).
- **DH:** Zayıf DH grubu (< 2048 bit), Logjam (export DH) ve anonim DH. Başlıklar nmap `ssl-dh-params` ile aynıdır.
- **Sıkıştırma:** DEFLATE teklif edilip sunucunun kabul edip etmediğine bakılır (CRIME).
- **Sertifika:** `ssl` modülüyle alınır, DER küçük bir ASN.1 ayrıştırıcıyla okunur (subject, issuer, SAN, anahtar tipi/uzunluğu, imza algoritması, geçerlilik, self-signed).
- **STARTTLS:** SMTP, FTP (`AUTH TLS`), IMAP, POP3 (`STLS`) ve RDP (TLS üzerinden RDP).
- **SSH:** Sunucunun şifrelemeden gönderdiği KEXINIT paketinden kex, host key, şifreleme, MAC ve sıkıştırma listeleri.
- **RDP:** X.224 Connection Request ile Native RDP, SSL, CredSSP (NLA) ve Early User Auth desteği. Native RDP kabul ediliyorsa (NLA zorunlu değil) zayıf işaretlenir. RDP TLS destekliyorsa TLS cipher'ları ve sertifika da taranır.

nmap motorundan farkları:

- Cipher isimleri OpenSSL formatındadır (`ECDHE-RSA-AES128-GCM-SHA256`); `detail` sütununda IANA cipher kodu (`id=0xC02F`) ve kex bilgisi yer alır.
- nmap'in A–F notu ve `least-strength` satırı yoktur; zayıflık isim, sürüm ve anahtar uzunluğu kurallarıyla belirlenir.
- SSLv2 taranmaz. Native RDP'nin şifreleme seviyesi (40/56/128-bit) okunmaz.

### sslscan ile doğrulama (`--verify`)

`--verify` verilirse nmap taramasından sonra **sadece TLS/sertifika/DH tarafında zayıf bulgusu olan** açık hedefler bir de `sslscan` ile taranır. Temiz hedefler ve SSH/RDP portları tekrar taranmaz.

- nmap'in zayıf bulduğu her satıra `verified` sütununda `CONFIRMED`, `NOT-CONFIRMED` ya da `N/A` (karşılaştırılamıyor) yazılır.
- sslscan'e özgü ek kontroller eklenir: Heartbleed, güvensiz renegotiation, TLS Fallback SCSV, key exchange grupları.
- STARTTLS servislerinde uygun `--starttls-*` parametresi, nmap'in tespit ettiği servise göre otomatik seçilir.

## Kurulum

### Windows (nmap yok, kurulum izni yok)

Sadece Python 3.7+ gerekir. `tlsscan.py` ve `pyscan.py` dosyalarını **aynı klasöre** kopyalamanız yeterli:

```powershell
python --version
python tlsscan.py -i targets.txt
```

nmap bulunamadığında Python motoru otomatik seçilir (açıkça seçmek için `--engine python`). sslscan olmadığından `--verify` verilirse uyarı verip atlanır. CSV dosyaları Excel'de Türkçe karakterler doğru görünsün diye UTF-8 BOM ile yazılır. Not Defteri'yle kaydedilmiş (BOM'lu) hedef listeleri de sorunsuz okunur.

### Linux / Kali

Gereksinimler: Python 3.7+, nmap (7.90+ önerilir, TLS 1.3 desteği için), sslscan (sadece `--verify` için). Ek bir Python paketi gerekmez. nmap yoksa Python motoru kullanılır.

Kali'de ikisi de hazır gelir. Diğer Debian/Ubuntu sistemlerinde:

```bash
sudo apt install nmap sslscan python3
```

Kontrol:

```bash
nmap --version
sslscan --version
ls /usr/share/nmap/scripts/ | grep -E "ssl-enum-ciphers|ssl-cert.nse|ssl-dh-params|ssh2-enum-algos|rdp-enum-encryption"
```

Script `-sT` (connect scan) kullandığı için root yetkisi gerektirmez.

## Kullanım

Hedef listesi: her satıra bir hedef. `#` ile başlayan satırlar yorum sayılır, aynı hedef birden fazla yazılmışsa bir kez taranır.

```text
# targets.txt
10.0.0.5:443
10.0.0.6:22
10.0.0.7:3389
mail.example.com:587
[2001:db8::1]:8443
```

Çalıştırma:

```bash
# Temel tarama
python3 tlsscan.py -i targets.txt

# 8 paralel nmap, sslscan doğrulaması ve JSON çıktısıyla
python3 tlsscan.py -i targets.txt -t 8 --verify -j sonuc.json
```

| Parametre | Varsayılan | Açıklama |
|---|---|---|
| `-i, --input` | (zorunlu) | `ip:port` listesi |
| `-o, --output` | `tls_results.csv` | Detay CSV (her algoritma bir satır) |
| `-s, --summary` | `tls_summary.csv` | Özet CSV (her hedef bir satır) |
| `-j, --json` | – | Tüm sonuçları JSON olarak da yaz |
| `-t, --threads` | `8` | Aynı anda çalışacak nmap sayısı |
| `--engine` | `auto` | `auto` (nmap varsa nmap), `nmap` ya da `python` |
| `--timeout` | `120` | nmap motoru: hedef başına NSE script timeout'u (saniye) |
| `--conn-timeout` | `5` | Python motoru: bağlantı/okuma timeout'u (saniye) |
| `--verify` | kapalı | Zayıf TLS/CERT/DH bulgularını sslscan ile doğrula |
| `--verify-threads` | `4` | Aynı anda çalışacak sslscan sayısı |

İlerleme stderr'e yazılır:

```text
[*] 3 hedef taranacak (3 paralel)
[1/3] scanme.nmap.org:22        open      SSH  weak=22
[2/3] example.com:443           open      TLSv1.0,TLSv1.1,TLSv1.2,TLSv1.3  weak=5
[*] sslscan doğrulaması: 1 hedef
[v 1/1] example.com:443           ok confirmed=4/4
```

## Çıktılar

### `tls_results.csv`: detay

Sütunlar: `target, service, protocol, version, category, algorithm, detail, weak, verified`

| protocol | category değerleri |
|---|---|
| `TLS` | `version`, `cipher` (detail: `grade=… kex=…`), `compression`, `warning`, `least-strength` |
| `CERT` | `subject`, `issuer`, `san`, `public-key`, `signature`, `validity` |
| `DH` | `dh-params` (detail: VULNERABLE / NOT VULNERABLE + modulus bilgisi) |
| `SSH` | `kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms`, `mac_algorithms`, `compression_algorithms` |
| `RDP` | `rdp-encryption` |
| `SSLSCAN` | `heartbleed`, `renegotiation`, `fallback-scsv`, `kex-group` (sadece `--verify` ile) |

Örnek:

```csv
example.com:443,ssl/http (Cloudflare http proxy),TLS,TLSv1.0,cipher,TLS_RSA_WITH_3DES_EDE_CBC_SHA,grade=C kex=rsa 2048,YES,CONFIRMED
```

Zayıf bulguları süzmek için: `grep ',YES,' tls_results.csv`

### `tls_summary.csv`: özet

Her hedef için tek satır: `target, state, service, tls_versions, cert_cn, cert_issuer, cert_key, cert_sig, cert_not_after, cert_expired, cert_self_signed, dh_issues, ssh, rdp, sslscan_status, sslscan_confirmed, heartbleed, insecure_reneg, fallback_scsv, kex_groups, weak_count, weak_items`

`state` değerleri: `open`, `closed`, `filtered`, `timeout`, `nmap-error`, `no-result`.

## Dikkat edilmesi gerekenler

- **IP ile taramada SNI gönderilmez.** Sunucu varsayılan sertifikasını döner. Aynı IP'de birden fazla site varsa ve belirli bir sitenin sertifikası lazımsa listede hostname kullanın (`site.example.com:443`).
- **Paralellik:** Bazı sunucular ve WAF/IPS'ler yoğun TLS el sıkışmalarını engeller; hedef `filtered` görünür ya da sonuç eksik gelir. Uzun listelerde `-t 4–8` önerilir. `filtered`, `timeout` ya da `sslscan_status=failed` çıkan hedefleri daha sonra tek tek yeniden tarayın.
- **`NOT-CONFIRMED`** her zaman yanlış alarm demek değildir. Sistemdeki OpenSSL'e bağlı derlenen sslscan bazı eski protokolleri deneyemeyebilir. Bu satırları elle kontrol edin, örneğin: `openssl s_client -connect host:port -tls1`
- **Süre:** İki motor da her sürüm/cipher için ayrı el sıkışma yapar; bir TLS hedefi birkaç saniyeden birkaç dakikaya kadar sürebilir. Python motoru genelde daha hızlıdır (example.com: ~10 sn).
- Script'i sadece **taranma izni olan** sistemlerde kullanın.
