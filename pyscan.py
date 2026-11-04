"""
nmap gerektirmeyen tarama motoru (sadece Python standart kütüphanesi).

- TLS/SSL: ClientHello paketleri elle oluşturulur, ServerHello okunur. Böylece
  sonuç yerel OpenSSL'in desteklediği cipher'lara bağlı kalmaz (SSLv3, RC4,
  EXPORT, NULL gibi eski cipher'lar da tespit edilir).
  Kabul edilen cipher'lar eleme yöntemiyle bulunur: tüm liste teklif edilir,
  sunucunun seçtiği çıkarılır, sunucu reddedene kadar tekrarlanır.
- Sertifika: ssl modülüyle alınır, DER küçük bir ASN.1 ayrıştırıcıyla okunur.
- DH: ServerKeyExchange mesajından DH modulus uzunluğu / ECDHE eğrisi okunur.
- STARTTLS: SMTP, IMAP, POP3, FTP ve RDP (TLS üzerinden RDP) desteklenir.
- SSH: Sunucunun şifresiz gönderdiği KEXINIT paketinden algoritma listeleri.
- RDP: X.224 Connection Request ile desteklenen güvenlik protokolleri.

Çıktı formatı tlsscan.py'deki nmap motoruyla aynıdır.
"""
import ipaddress
import os
import re
import socket
import ssl
import struct
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------
VERSIONS = {"SSLv3": 0x0300, "TLSv1.0": 0x0301, "TLSv1.1": 0x0302, "TLSv1.2": 0x0303}
WEAK_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

# Modern OpenSSL'de bulunmayabilecek eski cipher'lar (OpenSSL isimleriyle)
LEGACY_CIPHERS = {
    0x0001: "NULL-MD5", 0x0002: "NULL-SHA", 0x0003: "EXP-RC4-MD5", 0x0004: "RC4-MD5",
    0x0005: "RC4-SHA", 0x0006: "EXP-RC2-CBC-MD5", 0x0007: "IDEA-CBC-SHA",
    0x0008: "EXP-DES-CBC-SHA", 0x0009: "DES-CBC-SHA", 0x000A: "DES-CBC3-SHA",
    0x0011: "EXP-DHE-DSS-DES-CBC-SHA", 0x0012: "DHE-DSS-DES-CBC-SHA",
    0x0013: "DHE-DSS-DES-CBC3-SHA", 0x0014: "EXP-DHE-RSA-DES-CBC-SHA",
    0x0015: "DHE-RSA-DES-CBC-SHA", 0x0016: "DHE-RSA-DES-CBC3-SHA",
    0x0017: "EXP-ADH-RC4-MD5", 0x0018: "ADH-RC4-MD5", 0x0019: "EXP-ADH-DES-CBC-SHA",
    0x001A: "ADH-DES-CBC-SHA", 0x001B: "ADH-DES-CBC3-SHA", 0x0034: "ADH-AES128-SHA",
    0x003A: "ADH-AES256-SHA", 0x003B: "NULL-SHA256", 0x0062: "EXP1024-DES-CBC-SHA",
    0x0064: "EXP1024-RC4-SHA", 0x006C: "ADH-AES128-SHA256", 0x006D: "ADH-AES256-SHA256",
    0x00A6: "ADH-AES128-GCM-SHA256", 0x00A7: "ADH-AES256-GCM-SHA384",
    0x0041: "CAMELLIA128-SHA", 0x0084: "CAMELLIA256-SHA", 0x0096: "SEED-SHA",
    0xC001: "ECDH-ECDSA-NULL-SHA", 0xC002: "ECDH-ECDSA-RC4-SHA",
    0xC003: "ECDH-ECDSA-DES-CBC3-SHA", 0xC004: "ECDH-ECDSA-AES128-SHA",
    0xC005: "ECDH-ECDSA-AES256-SHA", 0xC006: "ECDHE-ECDSA-NULL-SHA",
    0xC007: "ECDHE-ECDSA-RC4-SHA", 0xC008: "ECDHE-ECDSA-DES-CBC3-SHA",
    0xC00B: "ECDH-RSA-NULL-SHA", 0xC00C: "ECDH-RSA-RC4-SHA",
    0xC00D: "ECDH-RSA-DES-CBC3-SHA", 0xC00E: "ECDH-RSA-AES128-SHA",
    0xC00F: "ECDH-RSA-AES256-SHA", 0xC010: "ECDHE-RSA-NULL-SHA",
    0xC011: "ECDHE-RSA-RC4-SHA", 0xC012: "ECDHE-RSA-DES-CBC3-SHA",
    0xC015: "AECDH-NULL-SHA", 0xC016: "AECDH-RC4-SHA", 0xC017: "AECDH-DES-CBC3-SHA",
    0xC018: "AECDH-AES128-SHA", 0xC019: "AECDH-AES256-SHA",
    # Yerel OpenSSL listesi boş gelirse diye yaygın modern cipher'lar
    0x002F: "AES128-SHA", 0x0035: "AES256-SHA", 0x003C: "AES128-SHA256",
    0x003D: "AES256-SHA256", 0x009C: "AES128-GCM-SHA256", 0x009D: "AES256-GCM-SHA384",
    0x0033: "DHE-RSA-AES128-SHA", 0x0039: "DHE-RSA-AES256-SHA",
    0x0067: "DHE-RSA-AES128-SHA256", 0x006B: "DHE-RSA-AES256-SHA256",
    0x009E: "DHE-RSA-AES128-GCM-SHA256", 0x009F: "DHE-RSA-AES256-GCM-SHA384",
    0xC009: "ECDHE-ECDSA-AES128-SHA", 0xC00A: "ECDHE-ECDSA-AES256-SHA",
    0xC013: "ECDHE-RSA-AES128-SHA", 0xC014: "ECDHE-RSA-AES256-SHA",
    0xC023: "ECDHE-ECDSA-AES128-SHA256", 0xC024: "ECDHE-ECDSA-AES256-SHA384",
    0xC027: "ECDHE-RSA-AES128-SHA256", 0xC028: "ECDHE-RSA-AES256-SHA384",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256", 0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305", 0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xCCAA: "DHE-RSA-CHACHA20-POLY1305",
}
TLS13_CIPHERS = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
                 0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
                 0x1305: "TLS_AES_128_CCM_8_SHA256"}
GROUPS = {0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
          0x001E: "x448", 0x0016: "secp256k1", 0x0015: "secp224r1", 0x0013: "secp192r1",
          0x001A: "brainpoolP256r1", 0x001B: "brainpoolP384r1", 0x001C: "brainpoolP512r1",
          0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
          0x0103: "ffdhe6144", 0x0104: "ffdhe8192", 0x000F: "secp160k1",
          0x0010: "secp160r1", 0x0011: "secp160r2", 0x0012: "secp192k1"}
# Grupların yaklaşık güvenlik biti (112 altı zayıf)
GROUP_BITS = {"x25519": 128, "x448": 224, "secp256r1": 128, "secp384r1": 192,
              "secp521r1": 256, "secp256k1": 128, "secp224r1": 112, "secp192r1": 96,
              "secp192k1": 96, "secp160k1": 80, "secp160r1": 80, "secp160r2": 80,
              "brainpoolP256r1": 128, "brainpoolP384r1": 192, "brainpoolP512r1": 256,
              "ffdhe2048": 112, "ffdhe3072": 128, "ffdhe4096": 152, "ffdhe6144": 176,
              "ffdhe8192": 192}
FFDHE = {0x0100, 0x0101, 0x0102, 0x0103, 0x0104}
SIGALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0401,
           0x0501, 0x0601, 0x0303, 0x0203, 0x0201, 0x0402, 0x0202, 0x0301, 0x0302]
# Bazı sunucular büyük ClientHello'ya yanıt vermez (ör. ~300 bayt üstü); nmap gibi
# cipher listesi parçalar halinde gönderilir.
CHUNK = 64
# Servis tespiti için yaygın, küçük bir cipher listesi
DETECT_CIPHERS = [0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9, 0xC013, 0xC014, 0xC009,
                  0xC00A, 0x009E, 0x009F, 0x0033, 0x0039, 0x009C, 0x009D, 0x002F, 0x0035,
                  0x003C, 0x003D, 0x000A, 0x0005, 0x0004, 0x0016, 0x0009]
TLS12_ONLY = re.compile(r"GCM|CCM|CHACHA|POLY1305|SHA256|SHA384", re.I)
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

WEAK_CIPHER = re.compile(r"NULL|EXP|ADH|AECDH|anon|RC4|RC2|DES|MD5|IDEA", re.I)
WEAK_SSH = re.compile(
    r"(^|-)cbc|arcfour|3des|blowfish|cast128|hmac-md5|hmac-sha1-96|umac-64(?!-etm)|"
    r"diffie-hellman-group1-|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|"
    r"gss-.*sha1|^ssh-dss|^none$", re.I)


def build_cipher_table():
    table = dict(LEGACY_CIPHERS)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
        for c in ctx.get_ciphers():
            cid = c["id"] & 0xFFFF
            if cid >> 8 != 0x13:
                table.setdefault(cid, c["name"])
    except (ssl.SSLError, ValueError):
        pass
    return table


CIPHERS = build_cipher_table()


# ---------------------------------------------------------------------------
# Bağlantı ve STARTTLS
# ---------------------------------------------------------------------------
class ScanError(Exception):
    pass


def _read_lines(s, done, limit=16384):
    buf = b""
    while len(buf) < limit:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        lines = buf.decode("latin-1").splitlines()
        if buf.endswith(b"\n") and lines and done(lines[-1]):
            return lines
    raise ScanError("STARTTLS yanıtı alınamadı")


def _read_until(s, done, limit=65536):
    buf = b""
    while len(buf) < limit:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
        if done(buf):
            return buf
    raise ScanError("STARTTLS yanıtı alınamadı")


# LDAP ExtendedRequest: StartTLS (OID 1.3.6.1.4.1.1466.20037)
LDAP_STARTTLS = bytes.fromhex("301d02010177188016") + b"1.3.6.1.4.1.1466.20037"
PG_SSLREQUEST = bytes.fromhex("0000000804d2162f")
MYSQL_CLIENT_SSL = 0x0800


def _ldap_done(b):
    """Tam bir LDAP (BER) mesajı geldi mi?"""
    if len(b) < 2:
        return False
    if b[1] < 0x80:
        return len(b) >= 2 + b[1]
    n = b[1] & 0x7F
    return len(b) >= 2 + n and len(b) >= 2 + n + int.from_bytes(b[2:2 + n], "big")


def _code_done(line):
    return bool(re.match(r"^\d{3} ", line))


def rdp_neg_request(protocols):
    return (b"\x03\x00\x00\x13" + b"\x0e\xe0\x00\x00\x00\x00\x00" +
            b"\x01\x00\x08\x00" + struct.pack("<I", protocols))


def rdp_neg_response(s):
    data = b""
    while len(data) < 11:
        chunk = s.recv(64)
        if not chunk:
            break
        data += chunk
    if len(data) < 11 or data[0] != 3:
        return None
    if len(data) >= 19 and data[11] == 0x02:
        return ("ok", struct.unpack("<I", data[15:19])[0])
    if len(data) >= 19 and data[11] == 0x03:
        return ("fail", struct.unpack("<I", data[15:19])[0])
    return ("ok", 0)  # müzakere verisi yok: sadece standart RDP


def do_starttls(s, kind, host=""):
    if kind == "ldap":
        s.sendall(LDAP_STARTTLS)
        resp = _read_until(s, _ldap_done)
        i = resp.find(b"\x78")  # ExtendedResponse
        if i < 0 or resp.find(b"\x0a\x01\x00", i) < 0:
            raise ScanError("LDAP StartTLS reddedildi")
    elif kind == "psql":
        s.sendall(PG_SSLREQUEST)
        if _recv_exact(s, 1) != b"S":
            raise ScanError("PostgreSQL SSL desteklemiyor")
    elif kind == "mysql":
        hdr = _recv_exact(s, 4)
        if not hdr:
            raise ScanError("MySQL greeting alınamadı")
        pkt = _recv_exact(s, int.from_bytes(hdr[:3], "little"))
        if not pkt or pkt[0] != 0x0A:
            raise ScanError("MySQL greeting tanınmadı")
        p = pkt.index(b"\x00", 1) + 1 + 4 + 8 + 1  # sürüm, thread id, salt, filler
        caps = struct.unpack("<H", pkt[p:p + 2])[0]
        if not caps & MYSQL_CLIENT_SSL:
            raise ScanError("MySQL SSL desteklemiyor")
        flags = 0x1 | 0x200 | MYSQL_CLIENT_SSL | 0x8000 | 0x80000
        body = struct.pack("<IIB", flags, 16777216, 33) + b"\x00" * 23
        s.sendall(len(body).to_bytes(3, "little") + b"\x01" + body)
    elif kind in ("xmpp", "xmpp-server"):
        ns = "jabber:server" if kind == "xmpp-server" else "jabber:client"
        s.sendall((f"<?xml version='1.0'?><stream:stream to='{host}' xmlns='{ns}' "
                   "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
                   ).encode())
        feats = _read_until(s, lambda b: b"</stream:features>" in b or b"</stream:stream>" in b)
        if b"<starttls" not in feats:
            raise ScanError("XMPP STARTTLS sunmuyor")
        s.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        if b"<proceed" not in _read_until(s, lambda b: b"<proceed" in b or b"<failure" in b):
            raise ScanError("XMPP STARTTLS reddedildi")
    elif kind == "smtp":
        _read_lines(s, _code_done)
        s.sendall(b"EHLO tlsscan.local\r\n")
        _read_lines(s, _code_done)
        s.sendall(b"STARTTLS\r\n")
        if not _read_lines(s, _code_done)[-1].startswith("220"):
            raise ScanError("STARTTLS reddedildi")
    elif kind == "ftp":
        _read_lines(s, _code_done)
        s.sendall(b"AUTH TLS\r\n")
        if not _read_lines(s, _code_done)[-1].startswith("234"):
            raise ScanError("AUTH TLS reddedildi")
    elif kind == "imap":
        _read_lines(s, lambda l: l.startswith("* "))
        s.sendall(b"a1 STARTTLS\r\n")
        if not _read_lines(s, lambda l: l.startswith("a1 "))[-1].startswith("a1 OK"):
            raise ScanError("STARTTLS reddedildi")
    elif kind == "pop3":
        _read_lines(s, lambda l: l.startswith(("+OK", "-ERR")))
        s.sendall(b"STLS\r\n")
        if not _read_lines(s, lambda l: l.startswith(("+OK", "-ERR")))[-1].startswith("+OK"):
            raise ScanError("STLS reddedildi")
    elif kind == "rdp":
        s.sendall(rdp_neg_request(0x3))
        r = rdp_neg_response(s)
        if not r or r[0] != "ok" or r[1] == 0:
            raise ScanError("RDP TLS desteklemiyor")


class Conn:
    def __init__(self, host, port, timeout, starttls=None):
        self.host, self.port, self.timeout, self.starttls = host, port, timeout, starttls
        try:
            ipaddress.ip_address(host)
            self.sni = None
        except ValueError:
            self.sni = host

    def open(self):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            if self.starttls:
                do_starttls(s, self.starttls, self.host)
        except Exception:
            s.close()
            raise
        return s


# ---------------------------------------------------------------------------
# TLS ClientHello / ServerHello
# ---------------------------------------------------------------------------
def _ext(t, data):
    return struct.pack(">HH", t, len(data)) + data


def _u16list(values, lenbytes=2):
    data = b"".join(struct.pack(">H", v) for v in values)
    return len(data).to_bytes(lenbytes, "big") + data


def client_hello(version, ciphers, sni, tls13=False, compression=False, groups=None):
    groups = list(GROUPS) if groups is None else groups
    exts = b""
    if sni and (version >= 0x0301 or tls13):
        name = sni.encode("idna")
        entry = b"\x00" + struct.pack(">H", len(name)) + name
        exts += _ext(0x0000, struct.pack(">H", len(entry)) + entry)
    if version >= 0x0301 or tls13:
        exts += _ext(0x000A, _u16list(groups))
        exts += _ext(0x000B, b"\x01\x00")
        exts += _ext(0x000D, _u16list(SIGALGS))
    if tls13:
        exts += _ext(0x002B, b"\x02\x03\x04")
        # x25519 teklif ediliyorsa key_share gönder; yoksa boş key_share (sunucu HRR ile
        # desteklediği grubu bildirir)
        share = struct.pack(">HH", 0x001D, 32) + os.urandom(32) if 0x001D in groups else b""
        exts += _ext(0x0033, struct.pack(">H", len(share)) + share)
    suites = list(ciphers) if tls13 else list(ciphers) + [0x00FF]
    comp = b"\x02\x01\x00" if compression else b"\x01\x00"
    body = (struct.pack(">H", 0x0303 if tls13 else version) + os.urandom(32) + b"\x00" +
            _u16list(suites) + comp)
    if exts:
        body += struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = 0x0300 if version == 0x0300 else 0x0301
    return b"\x16" + struct.pack(">HH", rec, len(hs)) + hs


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_handshake(s, full, alert=None):
    """ServerHello'ya (full=True ise ServerHelloDone'a) kadar handshake mesajlarını okur.
    alert listesi verilirse gelen alert açıklama kodu ona eklenir."""
    msgs, buf, total = [], b"", 0
    while total < 65536:
        hdr = _recv_exact(s, 5)
        if not hdr:
            break
        ctype, _, ln = struct.unpack(">BHH", hdr)
        data = _recv_exact(s, ln)
        if ctype == 0x15 and data and len(data) >= 2 and alert is not None:
            alert.append(data[1])
        if data is None or ctype != 0x16:  # alert, CCS, şifreli veri ya da bozuk
            break
        total += ln
        buf += data
        while len(buf) >= 4:
            ln2 = int.from_bytes(buf[1:4], "big")
            if len(buf) < 4 + ln2:
                break
            t, body, buf = buf[0], buf[4:4 + ln2], buf[4 + ln2:]
            msgs.append((t, body))
            if t == 14 or (t == 2 and not full):
                return msgs
    return msgs


def parse_server_hello(b):
    ver = struct.unpack(">H", b[0:2])[0]
    random = b[2:34]
    p = 35 + b[34]
    info = {"version": ver, "cipher": struct.unpack(">H", b[p:p + 2])[0],
            "compression": b[p + 2], "hrr": random == HRR_RANDOM, "group": None,
            "reneg_ext": False}
    p += 3
    if p + 2 <= len(b):
        end = p + 2 + struct.unpack(">H", b[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            t, ln = struct.unpack(">HH", b[p:p + 4])
            d = b[p + 4:p + 4 + ln]
            if t == 0x002B and ln >= 2:
                info["version"] = struct.unpack(">H", d[:2])[0]
            elif t == 0x0033 and ln >= 2:
                info["group"] = struct.unpack(">H", d[:2])[0]
            elif t == 0xFF01:
                info["reneg_ext"] = True
            p += 4 + ln
    return info


def parse_kex(name, ske):
    """ServerKeyExchange'den kex bilgisi: ('ecdh', grup) ya da ('dh', bit)."""
    if not ske:
        return None
    if "ECDH" in name and ske[0] == 3 and len(ske) >= 3:
        gid = struct.unpack(">H", ske[1:3])[0]
        return ("ecdh", GROUPS.get(gid, f"0x{gid:04x}"))
    if re.search(r"DHE|EDH|ADH", name) and "ECDH" not in name:
        plen = struct.unpack(">H", ske[0:2])[0]
        return ("dh", int.from_bytes(ske[2:2 + plen], "big").bit_length())
    return None


def probe(conn, version, ciphers, tls13=False, full=False, compression=False, groups=None,
          alert=None):
    """Tek bir el sıkışma dener. Sonuç sözlüğü ya da None (reddedildi) döner."""
    try:
        s = conn.open()
    except (OSError, ScanError):
        return None
    try:
        s.sendall(client_hello(version, ciphers, conn.sni, tls13, compression, groups))
        msgs = read_handshake(s, full, alert)
    except (OSError, ValueError, IndexError, struct.error):
        return None
    finally:
        s.close()
    sh = next((b for t, b in msgs if t == 2), None)
    if not sh:
        return None
    try:
        info = parse_server_hello(sh)
    except (IndexError, struct.error):
        return None
    info["ske"] = next((b for t, b in msgs if t == 12), None)
    cert = next((b for t, b in msgs if t == 11), None)
    info["cert"] = None
    if cert and len(cert) > 6:
        ln = int.from_bytes(cert[3:6], "big")
        info["cert"] = cert[6:6 + ln]
    return info


def enum_version(conn, vname):
    """Bir TLS sürümünde kabul edilen cipher'ları eleme yöntemiyle bulur."""
    if vname == "TLSv1.3":
        remaining, ver, tls13, table = list(TLS13_CIPHERS), 0x0304, True, TLS13_CIPHERS
    else:
        remaining, ver, tls13, table = list(CIPHERS), VERSIONS[vname], False, CIPHERS
        if ver < 0x0303:
            # AEAD/SHA256+ cipher'lar sadece TLS 1.2'de geçerli; eski sürümlerde teklif
            # edilirse bazı sunucular (ör. çift sertifikalı) el sıkışmayı kesiyor.
            remaining = [c for c in remaining if not TLS12_ONLY.search(CIPHERS[c])]
    accepted, cert = [], None
    for start in range(0, len(remaining), CHUNK):
        chunk = remaining[start:start + CHUNK]
        while chunk:
            r = probe(conn, ver, chunk, tls13=tls13, full=not tls13)
            if not r or r["version"] != ver or r["cipher"] not in chunk:
                break
            name = table.get(r["cipher"], f"0x{r['cipher']:04X}")
            if tls13:
                kex = ("ecdh", GROUPS.get(r["group"], "?")) if r["group"] else None
            else:
                kex = parse_kex(name, r["ske"])
            accepted.append((r["cipher"], name, kex))
            cert = cert or r["cert"]
            chunk.remove(r["cipher"])

    pref = ""
    if len(accepted) >= 2:
        ids = [a[0] for a in accepted][:CHUNK]
        r1 = probe(conn, ver, ids, tls13=tls13)
        r2 = probe(conn, ver, ids[::-1], tls13=tls13)
        if r1 and r2:
            pref = "server" if r1["cipher"] == r2["cipher"] else "client"
    return accepted, pref, cert


def check_fallback_scsv(conn, versions):
    """TLS_FALLBACK_SCSV: en yüksek sürümden düşük bir sürümle SCSV gönderilir;
    sunucu inappropriate_fallback (86) alert'i dönerse koruma vardır."""
    order = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    supported = [v for v in order if v in versions]
    if len(supported) < 2:
        return None
    lower = supported[-2]
    alert = []
    r = probe(conn, VERSIONS[lower], DETECT_CIPHERS + [0x5600], alert=alert)
    if 86 in alert:
        return True
    if r and r["version"] == VERSIONS[lower]:
        return False
    return None  # belirsiz


def enum_groups(conn, versions, ecdhe_12):
    """Desteklenen key exchange gruplarını tek tek dener."""
    found = []
    if "TLSv1.3" in versions:
        for gid, name in GROUPS.items():
            r = probe(conn, 0x0304, list(TLS13_CIPHERS), tls13=True, groups=[gid])
            if r and r["version"] == 0x0304 and r["group"] == gid:
                found.append(("TLSv1.3", gid, name))
    if "TLSv1.2" in versions and ecdhe_12:
        for gid, name in GROUPS.items():
            if gid in FFDHE:
                continue
            r = probe(conn, 0x0303, ecdhe_12, full=True, groups=[gid])
            if r and r["version"] == 0x0303:
                ske = r["ske"]
                if ske and ske[0] == 3 and struct.unpack(">H", ske[1:3])[0] == gid:
                    found.append(("TLSv1.2", gid, name))
    return found


# ---------------------------------------------------------------------------
# Sertifika (DER) ayrıştırma
# ---------------------------------------------------------------------------
def _der(b, i):
    tag, ln = b[i], b[i + 1]
    i += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big")
        i += n
    return tag, b[i:i + ln], i + ln


def _children(b):
    out, i = [], 0
    while i < len(b):
        t, v, i = _der(b, i)
        out.append((t, v))
    return out


def _oid(v):
    parts, n = [v[0] // 40, v[0] % 40], 0
    for c in v[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


SIG_OIDS = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption", "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-SHA1", "2.16.840.1.101.3.4.3.2": "dsa-with-SHA256",
    "1.3.101.112": "ED25519", "1.3.101.113": "ED448",
}
CURVES = {"1.2.840.10045.3.1.7": ("prime256v1", 256), "1.3.132.0.34": ("secp384r1", 384),
          "1.3.132.0.35": ("secp521r1", 521), "1.3.132.0.33": ("secp224r1", 224),
          "1.2.840.10045.3.1.1": ("prime192v1", 192), "1.3.132.0.10": ("secp256k1", 256)}
NAME_OIDS = {"2.5.4.3": "commonName", "2.5.4.6": "countryName", "2.5.4.7": "localityName",
             "2.5.4.8": "stateOrProvinceName", "2.5.4.10": "organizationName",
             "2.5.4.11": "organizationalUnitName", "1.2.840.113549.1.9.1": "emailAddress"}


def _str(tag, v):
    if tag == 0x1E:
        return v.decode("utf-16-be", "replace")
    return v.decode("utf-8", "replace")


def _name(v):
    out = []
    for _, rdn in _children(v):
        for _, atv in _children(rdn):
            (ot, ov), (st, sv) = _children(atv)[:2]
            out.append((NAME_OIDS.get(_oid(ov), _oid(ov)), _str(st, sv)))
    return out


def _time(tag, v):
    s = v.decode("ascii", "replace").rstrip("Z")
    try:
        if tag == 0x17:
            yy = int(s[:2])
            s = ("19" if yy >= 50 else "20") + s
        return datetime.strptime(s[:14], "%Y%m%d%H%M%S").isoformat()
    except ValueError:
        return s


def parse_cert(der):
    cert = _children(_children(der)[0][1])
    tbs = _children(cert[0][1])
    if tbs[0][0] == 0xA0:
        tbs = tbs[1:]
    _, sig_alg, issuer, validity, subject, spki = tbs[:6]
    info = {"sig": SIG_OIDS.get(_oid(_children(sig_alg[1])[0][1]),
                                _oid(_children(sig_alg[1])[0][1])),
            "subject": _name(subject[1]), "issuer": _name(issuer[1]),
            "self_signed": subject[1] == issuer[1], "san": "", "curve": ""}
    (t1, v1), (t2, v2) = _children(validity[1])[:2]
    info["not_before"], info["not_after"] = _time(t1, v1), _time(t2, v2)

    alg, bitstr = _children(spki[1])[:2]
    alg_parts = _children(alg[1])
    koid = _oid(alg_parts[0][1])
    info["key_type"], info["key_bits"] = koid, 0
    if koid == "1.2.840.113549.1.1.1":
        n = _children(_children(bitstr[1][1:])[0][1])[0][1]
        info["key_type"], info["key_bits"] = "rsa", int.from_bytes(n, "big").bit_length()
    elif koid == "1.2.840.10045.2.1":
        cname, bits = CURVES.get(_oid(alg_parts[1][1]), (_oid(alg_parts[1][1]), 0))
        info["key_type"], info["key_bits"], info["curve"] = "ec", bits, cname
    elif koid == "1.2.840.10040.4.1":
        p = _children(alg_parts[1][1])[0][1]
        info["key_type"], info["key_bits"] = "dsa", int.from_bytes(p, "big").bit_length()
    elif koid in ("1.3.101.112", "1.3.101.113"):
        info["key_type"] = "ed25519" if koid.endswith("112") else "ed448"
        info["key_bits"] = 256 if koid.endswith("112") else 456

    for t, v in tbs[6:]:
        if t != 0xA3:
            continue
        for _, e in _children(_children(v)[0][1]):
            parts = _children(e)
            if _oid(parts[0][1]) == "2.5.29.17":
                names = []
                for gt, gv in _children(_children(parts[-1][1])[0][1]):
                    if gt == 0x82:
                        names.append("DNS:" + gv.decode("ascii", "replace"))
                    elif gt == 0x87:
                        names.append("IP Address:" + str(ipaddress.ip_address(gv)))
                info["san"] = ", ".join(names)
    return info


def fetch_cert_der(conn):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ssl.SSLError, ValueError, AttributeError):
        pass
    s = conn.open()
    try:
        with ctx.wrap_socket(s, server_hostname=conn.sni) as ts:
            return ts.getpeercert(binary_form=True)
    finally:
        s.close()


# ---------------------------------------------------------------------------
# SSH ve RDP
# ---------------------------------------------------------------------------
SSH_LISTS = ["kex_algorithms", "server_host_key_algorithms", "encryption_algorithms",
             None, "mac_algorithms", None, "compression_algorithms", None, None, None]


def ssh_kexinit(host, port, timeout):
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        buf = b""
        while b"\n" not in buf or not re.search(rb"(^|\n)SSH-[^\n]*\n", buf):
            chunk = s.recv(4096)
            if not chunk or len(buf) > 16384:
                raise ScanError("SSH banner alınamadı")
            buf += chunk
        m = re.search(rb"(^|\n)(SSH-[^\r\n]*)\r?\n", buf)
        banner = m.group(2).decode("latin-1")
        rest = buf[m.end():]
        s.sendall(b"SSH-2.0-tlsscan\r\n")
        while len(rest) < 5:
            chunk = s.recv(4096)
            if not chunk:
                raise ScanError("KEXINIT alınamadı")
            rest += chunk
        plen, padlen = struct.unpack(">IB", rest[:5])
        if plen > 65536:
            raise ScanError("Geçersiz SSH paketi")
        while len(rest) < 4 + plen:
            chunk = s.recv(4096)
            if not chunk:
                raise ScanError("KEXINIT eksik")
            rest += chunk
        payload = rest[5:4 + plen - padlen]
        if payload[0] != 20:
            raise ScanError("KEXINIT beklenirken farklı paket")
        p, lists = 17, []
        for _ in range(10):
            ln = struct.unpack(">I", payload[p:p + 4])[0]
            lists.append(payload[p + 4:p + 4 + ln].decode("latin-1"))
            p += 4 + ln
        return banner, lists
    finally:
        s.close()


# (etiket, istenen protokoller, başarı kontrolü: seçilen protokol)
RDP_PROTOCOLS = [("Native RDP", 0x0, lambda sel: sel == 0),
                 ("SSL", 0x1, lambda sel: sel == 1),
                 ("CredSSP (NLA)", 0x3, lambda sel: bool(sel & 0x2)),
                 ("CredSSP with Early User Auth", 0xB, lambda sel: bool(sel & 0x8))]
RDP_FAIL = {1: "SSL gerekli", 2: "SSL yasak", 3: "sertifika yok", 4: "tutarsız flag",
            5: "CredSSP (NLA) gerekli", 6: "SSL + kullanıcı doğrulama gerekli"}


def rdp_scan(host, port, timeout):
    results = []
    for label, proto, check in RDP_PROTOCOLS:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            try:
                s.sendall(rdp_neg_request(proto))
                r = rdp_neg_response(s)
            finally:
                s.close()
        except OSError:
            r = None
        if r is None:
            results.append((label, None, ""))
        elif r[0] == "ok":
            results.append((label, check(r[1]), ""))
        else:
            results.append((label, False, RDP_FAIL.get(r[1], f"kod {r[1]}")))
    return results


# ---------------------------------------------------------------------------
# Ana tarama
# ---------------------------------------------------------------------------
NOBANNER_STARTTLS = {389: "ldap", 3268: "ldap", 5432: "psql", 5222: "xmpp",
                     5269: "xmpp-server"}


def _dn(pairs):
    return "/".join(f"{k}={v}" for k, v in pairs)


def scan_target(host, port, timeout=5):
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    rows = []
    summary = {"target": target, "host": host, "port": port, "state": "open", "service": "",
               "svc_name": "", "tunnel": "", "tls_versions": [], "ssh": False, "rdp": False,
               "weak": [], "cert": {}, "dh": []}

    def add(protocol, version, category, algorithm, detail="", weak=False):
        rows.append(dict(target=target, service=summary["service"], protocol=protocol,
                         version=version, category=category, algorithm=algorithm,
                         detail=detail, weak="YES" if weak else "", verified=""))
        if weak:
            summary["weak"].append(f"{version or protocol}:{algorithm}")

    # 1) Bağlan ve sunucu önce konuşuyorsa banner'ı oku
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        summary["state"] = "closed"
        return rows, summary
    except socket.timeout:
        summary["state"] = "filtered"
        return rows, summary
    except OSError as e:
        summary["state"] = f"error: {e}"
        return rows, summary
    try:
        s.settimeout(min(timeout, 3))
        banner = s.recv(1024)
    except (socket.timeout, OSError):
        banner = b""
    finally:
        s.close()

    # 2) SSH
    if banner.startswith(b"SSH-") or b"\nSSH-" in banner:
        summary["ssh"], summary["svc_name"] = True, "ssh"
        try:
            ssh_banner, lists = ssh_kexinit(host, port, timeout)
        except (OSError, ScanError, IndexError, struct.error) as e:
            summary["service"] = "ssh"
            add("SSH", "", "error", str(e))
            return rows, summary
        summary["service"] = f"ssh ({ssh_banner})"
        proto = ssh_banner.split("-")[1] if ssh_banner.count("-") >= 2 else ""
        if proto in ("1.5", "1.99"):
            add("SSH", f"SSH-{proto}", "version", f"SSH-{proto}", "SSHv1 destekli", True)
        for cat, lst in zip(SSH_LISTS, lists):
            if cat:
                for alg in filter(None, lst.split(",")):
                    add("SSH", "SSH-2", cat, alg, "", bool(WEAK_SSH.search(alg)))
        return rows, summary

    # 3) STARTTLS türü
    starttls = None
    text = banner.decode("latin-1")
    if text.startswith("220"):
        starttls = "ftp" if (port in (21, 990) or "FTP" in text.upper()) else "smtp"
    elif text.startswith("* OK"):
        starttls = "imap"
    elif text.startswith("+OK"):
        starttls = "pop3"
    elif len(banner) >= 5 and banner[3] == 0 and banner[4] == 0x0A:
        starttls = "mysql"

    def detect(c):
        return probe(c, 0x0303, DETECT_CIPHERS) or \
            probe(c, 0x0304, list(TLS13_CIPHERS), tls13=True) or \
            probe(c, 0x0301, DETECT_CIPHERS) or probe(c, 0x0300, DETECT_CIPHERS)

    conn = Conn(host, port, timeout, starttls)
    is_tls = detect(conn)
    if not is_tls and not banner and port in NOBANNER_STARTTLS:
        # Sunucu önce konuşmuyorsa ve port bilinen bir STARTTLS portuysa
        starttls = NOBANNER_STARTTLS[port]
        conn = Conn(host, port, timeout, starttls)
        is_tls = detect(conn)

    # 4) TLS değilse RDP dene
    if not is_tls and not starttls:
        rdp = rdp_scan(host, port, timeout)
        if any(ok is not None for _, ok, _ in rdp):
            summary["rdp"], summary["svc_name"], summary["service"] = True, "rdp", "rdp"
            for label, ok, note in rdp:
                state = "SUCCESS" if ok else ("FAILED" if ok is False else "NO RESPONSE")
                add("RDP", "", "rdp-encryption", f"{label}: {state}", note,
                    label == "Native RDP" and bool(ok))
            if any(ok for label, ok, _ in rdp if label != "Native RDP"):
                conn = Conn(host, port, timeout, "rdp")
                is_tls = probe(conn, 0x0303, DETECT_CIPHERS) or \
                    probe(conn, 0x0304, list(TLS13_CIPHERS), tls13=True)
            if not is_tls:
                return rows, summary
        else:
            summary["service"] = "unknown"
            summary["state"] = "open (TLS/SSH/RDP değil)"
            return rows, summary
    elif not is_tls:
        summary["service"] = f"{starttls} (STARTTLS yok/başarısız)"
        return rows, summary

    if not summary["service"]:
        if conn.starttls:
            summary["svc_name"], summary["service"] = conn.starttls, f"{conn.starttls}/starttls"
        else:
            summary["svc_name"], summary["tunnel"], summary["service"] = "", "ssl", "ssl"
    else:
        summary["service"] += "/ssl"

    # 5) Sürüm ve cipher taraması
    raw_cert, dh_bits, anon, export_dh, ecdhe_all = None, [], False, False, []
    for vname in ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        accepted, pref, cert = enum_version(conn, vname)
        if not accepted:
            continue
        raw_cert = raw_cert or cert
        summary["tls_versions"].append(vname)
        add("TLS", vname, "version", vname, pref, vname in WEAK_VERSIONS)
        for cid, name, kex in accepted:
            kex_s = "rsa" if re.match(r"(EXP-|EXP1024-)?(RC4|DES|AES|CAMELLIA|SEED|IDEA|"
                                      r"NULL|RC2)", name) else ""
            if kex:
                kex_s = f"dh {kex[1]}" if kex[0] == "dh" else kex[1]
                if kex[0] == "dh":
                    dh_bits.append(kex[1])
            if re.search(r"ADH|AECDH", name):
                anon = True
            if "ECDHE" in name and vname != "TLSv1.3":
                ecdhe_all.append((vname, cid, name))
            if name.startswith("EXP") and "DH" in name:
                export_dh = True
            add("TLS", vname, "cipher", name,
                f"id=0x{cid:04X}" + (f" kex={kex_s}" if kex_s else ""),
                bool(WEAK_CIPHER.search(name)))

    # Sıkıştırma (CRIME), renegotiation, fallback SCSV, key exchange grupları
    extra = summary["tls_extra"] = {}
    legacy = [v for v in summary["tls_versions"] if v != "TLSv1.3"]
    if legacy:
        r = probe(conn, VERSIONS[legacy[-1]], DETECT_CIPHERS)
        if r:
            # RFC 5746: sunucu renegotiation_info uzantısıyla yanıt vermeli
            extra["reneg_insecure"] = not r["reneg_ext"]
            add("TLS", legacy[-1], "renegotiation",
                "secure (RFC 5746)" if r["reneg_ext"] else "Secure Renegotiation desteklenmiyor",
                "", not r["reneg_ext"])
    fb = check_fallback_scsv(conn, summary["tls_versions"])
    if fb is not None:
        extra["fallback_scsv"] = fb
        add("TLS", "", "fallback-scsv", "supported" if fb else "NOT supported",
            "downgrade koruması", not fb)
    ecdhe_12 = [c for v, c, n in ecdhe_all if v == "TLSv1.2"][:CHUNK]
    groups = enum_groups(conn, summary["tls_versions"], ecdhe_12)
    extra["groups"] = sorted({n for _, _, n in groups})
    for v, gid, name in groups:
        bits = GROUP_BITS.get(name, 0)
        add("TLS", v, "kex-group", name, f"id=0x{gid:04x} bits={bits or '?'}",
            0 < bits < 112)

    if legacy:
        r = probe(conn, VERSIONS[legacy[-1]], DETECT_CIPHERS, compression=True)
        if r and r["compression"] == 1:
            add("TLS", legacy[-1], "compression", "DEFLATE", "CRIME riski", True)

    # 6) DH
    if dh_bits or anon or export_dh:
        mn = min(dh_bits) if dh_bits else 0
        checks = [
            ("Diffie-Hellman Key Exchange Insufficient Group Strength",
             bool(dh_bits) and mn < 2048, f"en küçük modulus: {mn} bit" if dh_bits else ""),
            ("Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)",
             export_dh or (bool(dh_bits) and mn <= 512), ""),
            ("Anonymous Diffie-Hellman Key Exchange MitM Vulnerability", anon, ""),
        ]
        for title, vuln, detail in checks:
            add("DH", "", "dh-params", title,
                f"{'VULNERABLE' if vuln else 'NOT VULNERABLE'} {detail}".strip(), vuln)
            if vuln:
                summary["dh"].append(title)

    # 7) Sertifika
    der = None
    try:
        der = fetch_cert_der(conn)
    except Exception:
        der = raw_cert
    if der:
        try:
            c = parse_cert(der)
        except Exception:
            c = None
        if c:
            cn = next((v for k, v in c["subject"] if k == "commonName"), "")
            key = f"{c['key_type']} {c['key_bits']}".strip()
            key_weak = (c["key_type"] in ("rsa", "dsa") and 0 < c["key_bits"] < 2048) or \
                       (c["key_type"] == "ec" and 0 < c["key_bits"] < 256)
            sig_weak = bool(re.search(r"md2|md5|sha1", c["sig"], re.I))
            try:
                expired = datetime.fromisoformat(c["not_after"]) < \
                    datetime.now(timezone.utc).replace(tzinfo=None)
            except ValueError:
                expired = False
            add("CERT", "", "subject", _dn(c["subject"]))
            add("CERT", "", "issuer", _dn(c["issuer"]),
                "self-signed" if c["self_signed"] else "", c["self_signed"])
            if c["san"]:
                add("CERT", "", "san", c["san"])
            add("CERT", "", "public-key", key, c["curve"], key_weak)
            add("CERT", "", "signature", c["sig"], "", sig_weak)
            add("CERT", "", "validity", f"{c['not_before']} -> {c['not_after']}",
                "EXPIRED" if expired else "", expired)
            summary["cert"] = {"cn": cn, "issuer": _dn(c["issuer"]), "key": key,
                               "sig": c["sig"], "not_after": c["not_after"],
                               "expired": expired, "self_signed": c["self_signed"]}
    return rows, summary
