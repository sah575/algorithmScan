#!/usr/bin/env python3
"""
ip:port listesini tarar; TLS/SSL sürümlerini ve cipher'ları, SSH algoritmalarını
ve RDP şifreleme bilgisini nmap NSE scriptleriyle çıkarır.

Kullanım:
    python3 tlsscan.py -i targets.txt -o sonuc.csv -t 10

targets.txt formatı (her satır bir hedef, # ile yorum):
    10.0.0.5:443
    10.0.0.6:22
    [2001:db8::1]:8443
"""
import argparse
import csv
import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

NSE_SCRIPTS = "ssl-enum-ciphers,ssl-cert,ssl-dh-params,ssh2-enum-algos,rdp-enum-encryption"

# Zayıf kabul edilen desenler (rapor için işaretleme)
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
WEAK_TLS_CIPHER = re.compile(r"NULL|EXPORT|anon|RC4|DES|MD5|IDEA|RC2", re.I)
WEAK_SSH = re.compile(
    r"(^|-)cbc|arcfour|3des|blowfish|cast128|hmac-md5|hmac-sha1-96|umac-64(?!-etm)|"
    r"diffie-hellman-group1-|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|"
    r"gss-.*sha1|^ssh-dss|^none$",
    re.I,
)

FIELDS = ["target", "service", "protocol", "version", "category", "algorithm",
          "detail", "weak", "grade", "verified"]

# ---------------------------------------------------------------------------
# Cipher suite kademeli notlandırma (PQC envanter çalışmasının mantığına göre)
# Eksenler: şifreleme modu (AEAD > CBC), hash (SHA-2 > SHA-1 > MD5/yok),
# anahtar uzunluğu (256 > 128; kuantum/Grover 128'i efektif 64 bite indirir) ve
# eski/kırık primitifler. Çalışmadaki Table2/PQC etiketleriyle aynı set kullanılır.
# ---------------------------------------------------------------------------
GRADE_WEAK = {"Zayıf", "Çok Zayıf", "Zayıf (Deprecated)"}
GRADE_ORDER = ["Güçlü", "Orta", "Orta (SHA1)", "Zayıf", "Çok Zayıf",
               "Zayıf (Deprecated)", "Unclassified"]


def classify_cipher(name):
    """Cipher adını (OpenSSL ya da IANA biçimi) kademeli nota çevirir."""
    n = (name or "").upper().replace("-", "_")
    if not n or n.startswith("0X"):
        return ""  # ham id, isim yok
    if "NULL" in n:
        return "Zayıf (Deprecated)"              # şifrelemesiz
    if "EXPORT" in n or n.startswith("EXP"):
        return "Çok Zayıf"                        # export-grade
    if any(t in n for t in ("RC4", "RC2", "3DES", "DES_EDE", "DES_CBC", "_DES_",
                            "MD5", "IDEA", "SEED")):
        return "Zayıf (Deprecated)"              # eski/kırık primitifler
    bits = 256 if "256" in n else (192 if "192" in n else (128 if "128" in n else 0))
    if "SHA384" in n or "SHA256" in n or "SHA512" in n:
        sha = 2
    elif n.endswith("SHA") or "_SHA_" in n:
        sha = 1
    else:
        sha = 0
    aead = "GCM" in n or "CCM" in n or "CHACHA20" in n or "POLY1305" in n
    if aead:
        return "Güçlü"                            # AEAD
    if sha == 2:
        return "Orta"                             # CBC + SHA-2
    if sha == 1:
        if bits >= 256:
            return "Orta (SHA1)"                  # 256-bit CBC + SHA-1
        if "ECDHE" in n or "AECDH" in n:
            return "Zayıf"                        # 128-bit SHA-1 ama eliptik FS
        return "Çok Zayıf"                        # 128-bit SHA-1, FS yok
    return "Unclassified"


def parse_target(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = re.match(r"^\[(.+)\]:(\d+)$", line) or re.match(r"^([^:\s]+):(\d+)$", line)
    if not m:
        print(f"[!] Geçersiz satır atlandı: {line}", file=sys.stderr)
        return None
    return m.group(1), int(m.group(2))


def run_nmap(host, port, timeout):
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    # -n hostname hedeflerde SNI'yi bozuyor (yanlış/varsayılan sertifika döner),
    # bu yüzden sadece IP hedeflerde kullanılıyor.
    cmd = ["nmap", "-Pn", "-sT", "-sV", "--version-light", "-p", str(port),
           "--script", NSE_SCRIPTS, "--script-args", "vulns.showall",
           "--script-timeout", f"{timeout}s", "-oX", "-"]
    if is_ip:
        cmd.insert(1, "-n")
    if ":" in host:
        cmd.insert(1, "-6")
    cmd.append(host)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 3 + 60)
    return proc.stdout


def elem_text(table, key):
    e = table.find(f"elem[@key='{key}']")
    return e.text if e is not None else ""


def parse_xml(xml_text, target):
    rows, summary = [], {"target": target, "state": "unknown", "service": "",
                         "tls_versions": [], "ssh": False, "rdp": False, "weak": [],
                         "cert": {}, "dh": []}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        summary["state"] = "nmap-error"
        return rows, summary

    port = root.find(".//port")
    if port is None:
        summary["state"] = "no-result"
        return rows, summary
    summary["state"] = port.find("state").get("state")
    svc = port.find("service")
    service = ""
    if svc is not None:
        service = svc.get("name", "")
        if svc.get("tunnel"):
            service = f"{svc.get('tunnel')}/{service}"
        if svc.get("product"):
            service += f" ({svc.get('product')} {svc.get('version', '')}".rstrip() + ")"
    summary["service"] = service
    if svc is not None:
        summary["svc_name"] = svc.get("name", "")
        summary["tunnel"] = svc.get("tunnel", "")

    def add(protocol, version, category, algorithm, detail="", weak=False):
        rows.append(dict(target=target, service=service, protocol=protocol,
                         version=version, category=category, algorithm=algorithm,
                         detail=detail, weak="YES" if weak else "", verified=""))
        if weak:
            summary["weak"].append(f"{version or protocol}:{algorithm}")

    for script in port.findall("script"):
        sid = script.get("id")

        if sid == "ssl-enum-ciphers":
            for ver in script.findall("table"):
                v = ver.get("key")
                summary["tls_versions"].append(v)
                v_weak = v in WEAK_TLS_VERSIONS
                add("TLS", v, "version", v, elem_text(ver, "cipher preference"), v_weak)
                ciphers = ver.find("table[@key='ciphers']")
                for c in (ciphers.findall("table") if ciphers is not None else []):
                    name, strength = elem_text(c, "name"), elem_text(c, "strength")
                    kex = elem_text(c, "kex_info")
                    weak = bool(WEAK_TLS_CIPHER.search(name)) or strength not in ("A", "")
                    add("TLS", v, "cipher", name, f"grade={strength} kex={kex}", weak)
                comp = ver.find("table[@key='compressors']")
                for c in (comp.findall("elem") if comp is not None else []):
                    if c.text and c.text != "NULL":
                        add("TLS", v, "compression", c.text, "CRIME riski", True)
                warns = ver.find("table[@key='warnings']")
                for w in (warns.findall("elem") if warns is not None else []):
                    add("TLS", v, "warning", w.text, "", True)
            least = script.find("elem[@key='least strength']")
            if least is not None:
                add("TLS", "", "least-strength", least.text, "", least.text != "A")

        elif sid == "ssl-cert":
            parse_cert(script, add, summary)

        elif sid == "ssl-dh-params":
            parse_dh(script, add, summary)

        elif sid == "ssh2-enum-algos":
            summary["ssh"] = True
            for t in script.findall("table"):
                cat = t.get("key")
                for e in t.findall("elem"):
                    # sıkıştırmada "none" normaldir; sadece şifreleme/MAC'te zayıftır
                    weak = bool(WEAK_SSH.search(e.text or "")) and cat != "compression_algorithms"
                    add("SSH", "SSH-2", cat, e.text, "", weak)

        elif sid == "rdp-enum-encryption":
            summary["rdp"] = True
            out = script.get("output", "")
            for line in out.splitlines():
                line = line.strip()
                if line:
                    weak = bool(re.search(r"40-bit|56-bit", line))
                    add("RDP", "", "rdp-encryption", line, "", weak)

    return rows, summary


def dn(table):
    if table is None:
        return ""
    return "/".join(f"{e.get('key')}={e.text}" for e in table.findall("elem"))


def parse_cert(script, add, summary):
    subj, issuer = script.find("table[@key='subject']"), script.find("table[@key='issuer']")
    cn = subj.findtext("elem[@key='commonName']", "") if subj is not None else ""
    pk = script.find("table[@key='pubkey']")
    ktype = pk.findtext("elem[@key='type']", "") if pk is not None else ""
    bits = pk.findtext("elem[@key='bits']", "") if pk is not None else ""
    curve = pk.findtext(".//elem[@key='curve']", "") if pk is not None else ""
    sig = script.findtext("elem[@key='sig_algo']", "")
    nb = script.findtext("table[@key='validity']/elem[@key='notBefore']", "")
    na = script.findtext("table[@key='validity']/elem[@key='notAfter']", "")
    san = ""
    for ext in script.findall("table[@key='extensions']/table"):
        if ext.findtext("elem[@key='name']", "") == "X509v3 Subject Alternative Name":
            san = ext.findtext("elem[@key='value']", "")

    try:
        b = int(bits)
    except ValueError:
        b = 0
    key_weak = (ktype in ("rsa", "dsa", "dh") and b < 2048) or (ktype == "ec" and 0 < b < 256)
    sig_weak = bool(re.search(r"md2|md4|md5|sha1With|sha1$|ecdsa-with-SHA1", sig, re.I))
    expired = False
    try:
        expired = datetime.fromisoformat(na) < datetime.now()
    except ValueError:
        pass
    self_signed = subj is not None and dn(subj) == dn(issuer)

    add("CERT", "", "subject", dn(subj))
    add("CERT", "", "issuer", dn(issuer), "self-signed" if self_signed else "", self_signed)
    if san:
        add("CERT", "", "san", san)
    add("CERT", "", "public-key", f"{ktype} {bits}".strip(), curve, key_weak)
    add("CERT", "", "signature", sig, "", sig_weak)
    add("CERT", "", "validity", f"{nb} -> {na}", "EXPIRED" if expired else "", expired)
    summary["cert"] = {"cn": cn, "issuer": dn(issuer), "key": f"{ktype} {bits}".strip(),
                       "sig": sig, "not_after": na, "expired": expired,
                       "self_signed": self_signed}


def parse_dh(script, add, summary):
    # vulns kütüphanesi çıktısı: her bulgu title/state/check_results içeren bir tablo
    for v in script.iter("table"):
        title = v.findtext("elem[@key='title']")
        if not title:
            continue
        state = v.findtext("elem[@key='state']", "")
        checks = [e.text for e in v.findall("table[@key='check_results']/elem") if e.text]
        detail = " ; ".join(" ".join(c.split()) for c in checks)
        vuln = "VULNERABLE" in state and "NOT" not in state
        add("DH", "", "dh-params", title, f"{state} {detail}".strip(), vuln)
        if vuln:
            summary["dh"].append(title)
    if not summary["dh"] and not list(script.iter("table")):
        out = " ".join(script.get("output", "").split())
        if out:
            add("DH", "", "dh-params", out)


def scan(host, port, timeout, engine="nmap", conn_timeout=5):
    if engine == "python":
        import pyscan
        return pyscan.scan_target(host, port, conn_timeout)
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    try:
        xml_text = run_nmap(host, port, timeout)
    except subprocess.TimeoutExpired:
        return [], {"target": target, "state": "timeout"}
    rows, summ = parse_xml(xml_text, target)
    summ["host"], summ["port"] = host, port
    return rows, summ


# --------------------------------------------------------------------------
# sslscan ile doğrulama (sadece zayıf bulgusu olan TLS hedefleri)
# --------------------------------------------------------------------------
STARTTLS_MAP = {"smtp": "smtp", "submission": "smtp", "imap": "imap", "pop3": "pop3",
                "ftp": "ftp", "ldap": "ldap", "xmpp": "xmpp", "xmpp-client": "xmpp",
                "xmpp-server": "xmpp", "mysql": "mysql", "postgresql": "psql",
                "psql": "psql", "irc": "irc"}
WARNING_KEYWORDS = ["3DES", "RC4", "EXPORT", "NULL", "anon", "DES", "MD5"]
VERIFY_PROTOCOLS = {"TLS", "CERT", "DH"}


def needs_verify(summ, rows):
    return summ.get("state") == "open" and any(
        r["weak"] and r["protocol"] in VERIFY_PROTOCOLS for r in rows)


def run_sslscan(summ, timeout):
    host, port = summ["host"], summ["port"]
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    with tempfile.NamedTemporaryFile(suffix=".xml") as tmp:
        cmd = ["sslscan", "--no-colour", "--iana-names", f"--xml={tmp.name}",
               "--connect-timeout=10", "--timeout=5"]
        svc = summ.get("svc_name", "")
        if summ.get("tunnel") != "ssl" and svc in STARTTLS_MAP:
            cmd.append(f"--starttls-{STARTTLS_MAP[svc]}")
        cmd.append(target)
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return tmp.read().decode(errors="replace")


def parse_sslscan(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    test = root.find("ssltest")
    if test is None:
        return None
    ss = {"protocols": set(), "ciphers": {}, "groups": [], "heartbleed": False,
          "reneg_insecure": False, "fallback": None, "compression": False, "cert": {}}
    for pr in test.findall("protocol"):
        if pr.get("enabled") == "1":
            t, v = pr.get("type"), pr.get("version")
            ss["protocols"].add(f"SSLv{v}" if t == "ssl" else f"TLSv{v}")
    ss["cipher_ids"] = set()
    for c in test.findall("cipher"):
        ss["ciphers"][(c.get("sslversion"), c.get("cipher"))] = c.attrib
        try:
            ss["cipher_ids"].add((c.get("sslversion"), int(c.get("id", ""), 16)))
        except ValueError:
            pass
    for g in test.findall("group"):
        ss["groups"].append((g.get("sslversion"), g.get("name"), g.get("bits")))
    ss["heartbleed"] = any(h.get("vulnerable") == "1" for h in test.findall("heartbleed"))
    rn = test.find("renegotiation")
    if rn is not None:
        ss["reneg_insecure"] = rn.get("supported") == "1" and rn.get("secure") != "1"
    fb = test.find("fallback")
    if fb is not None:
        ss["fallback"] = fb.get("supported") == "1"
    cp = test.find("compression")
    ss["compression"] = cp is not None and cp.get("supported") == "1"
    cert = test.find("certificates/certificate")
    if cert is not None:
        pk = cert.find("pk")
        ss["cert"] = {
            "sig": cert.findtext("signature-algorithm", ""),
            "pk_type": (pk.get("type", "") if pk is not None else "").lower(),
            "pk_bits": int(pk.get("bits", "0") or 0) if pk is not None else 0,
            "curve": pk.get("curve_name", "") if pk is not None else "",
            "expired": cert.findtext("expired", "") == "true",
            "self_signed": cert.findtext("self-signed", "") == "true",
        }
    return ss


def verify_row(r, ss):
    cat, ver, alg = r["category"], r["version"], r["algorithm"] or ""
    names = [n for (_, n) in ss["ciphers"]]
    c = ss["cert"]
    if r["protocol"] == "TLS":
        if cat == "version":
            ok = ver in ss["protocols"]
        elif cat == "cipher":
            m = re.search(r"id=0x([0-9A-Fa-f]{4})", r.get("detail", ""))
            if m:  # python motoru: OpenSSL ismi + id; id ile karşılaştır
                ok = (ver, int(m.group(1), 16)) in ss["cipher_ids"]
            else:  # nmap motoru: IANA ismi
                ok = (ver, alg) in ss["ciphers"]
        elif cat == "compression":
            ok = ss["compression"]
        elif cat == "warning":
            kw = [k for k in WARNING_KEYWORDS if k.lower() in alg.lower()]
            if not kw:
                return "N/A"
            ok = any(k.lower() in n.lower() for k in kw for n in names)
        else:
            return "N/A"
    elif r["protocol"] == "CERT":
        if not c:
            return "N/A"
        if cat == "public-key":
            ok = (c["pk_type"] in ("rsa", "dsa") and 0 < c["pk_bits"] < 2048) or \
                 (c["pk_type"] == "ec" and 0 < c["pk_bits"] < 128)  # EC: güvenlik biti
        elif cat == "signature":
            ok = bool(re.search(r"md2|md4|md5|sha1", c["sig"], re.I))
        elif cat == "validity":
            ok = c["expired"]
        elif cat == "issuer":
            ok = c["self_signed"]
        else:
            return "N/A"
    elif r["protocol"] == "DH":
        dh = [int(a.get("dhebits", 0)) for a in ss["ciphers"].values() if a.get("dhebits")]
        if "Insufficient" in alg or "Logjam" in alg or "EXPORT" in alg:
            ok = any(b < 2048 for b in dh)
        elif "Anonymous" in alg:
            ok = any("anon" in n for n in names)
        else:
            return "N/A"
    else:
        return ""
    return "CONFIRMED" if ok else "NOT-CONFIRMED"


def sslscan_extra_rows(summ, ss):
    base = dict(target=summ["target"], service=summ.get("service", ""),
                protocol="SSLSCAN", version="", detail="", verified="sslscan")
    rows = [dict(base, category="heartbleed",
                 algorithm="VULNERABLE" if ss["heartbleed"] else "not vulnerable",
                 weak="YES" if ss["heartbleed"] else ""),
            dict(base, category="renegotiation",
                 algorithm="insecure" if ss["reneg_insecure"] else "secure/not supported",
                 weak="YES" if ss["reneg_insecure"] else "")]
    if ss["fallback"] is not None:
        rows.append(dict(base, category="fallback-scsv",
                         algorithm="supported" if ss["fallback"] else "NOT supported",
                         weak="" if ss["fallback"] else "YES"))
    for v, name, bits in ss["groups"]:
        weak = bits.isdigit() and int(bits) < 112
        rows.append(dict(base, version=v, category="kex-group", algorithm=name,
                         detail=f"bits={bits}", weak="YES" if weak else ""))
    return rows


def verify_target(summ, rows, timeout):
    try:
        ss = parse_sslscan(run_sslscan(summ, timeout))
    except subprocess.TimeoutExpired:
        ss = None
    if ss is None:
        summ["sslscan"] = {"status": "failed"}
        return []
    total = confirmed = 0
    for r in rows:
        if r["weak"] and r["protocol"] in VERIFY_PROTOCOLS:
            r["verified"] = verify_row(r, ss)
            if r["verified"] in ("CONFIRMED", "NOT-CONFIRMED"):
                total += 1
                confirmed += r["verified"] == "CONFIRMED"
    summ["sslscan"] = {
        "status": "ok", "confirmed": f"{confirmed}/{total}",
        "heartbleed": ss["heartbleed"], "reneg_insecure": ss["reneg_insecure"],
        "fallback_scsv": ss["fallback"],
        "groups": sorted({n.split(" ")[0] for _, n, _ in ss["groups"]}),
    }
    extra = sslscan_extra_rows(summ, ss)
    summ["weak"].extend(f"sslscan:{r['category']}={r['algorithm']}" for r in extra if r["weak"])
    return extra


# --------------------------------------------------------------------------
# Okunabilir rapor (konsol + txt)
# --------------------------------------------------------------------------
CATEGORY_LABELS = {
    "version": "Sürüm", "cipher": "Cipher", "compression": "Sıkıştırma",
    "warning": "Uyarı", "least-strength": "En düşük not", "renegotiation": "Renegotiation",
    "fallback-scsv": "Fallback SCSV", "kex-group": "Key exchange grubu",
    "subject": "Subject", "issuer": "Issuer", "san": "SAN", "public-key": "Açık anahtar",
    "signature": "İmza algoritması", "validity": "Geçerlilik", "dh-params": "DH",
    "kex_algorithms": "Key exchange (kex)", "server_host_key_algorithms": "Host key",
    "encryption_algorithms": "Şifreleme", "mac_algorithms": "MAC",
    "compression_algorithms": "Sıkıştırma", "rdp-encryption": "Güvenlik protokolü",
    "heartbleed": "Heartbleed", "error": "Hata",
}
PROTOCOL_LABELS = {"TLS": "TLS/SSL", "CERT": "Sertifika", "DH": "Diffie-Hellman",
                   "SSH": "SSH", "RDP": "RDP", "SSLSCAN": "sslscan ek kontroller"}


def _mark(r):
    m = " [ZAYIF]" if r["weak"] else ""
    if r.get("verified") in ("CONFIRMED", "NOT-CONFIRMED"):
        m += f" [{r['verified']}]"
    return m


def build_report(summaries, rows):
    by_target = {}
    for r in rows:
        by_target.setdefault(r["target"], []).append(r)
    out = []
    for s in sorted(summaries, key=lambda s: s["target"]):
        out.append("=" * 78)
        out.append(f"{s['target']}   durum: {s.get('state', '')}   servis: "
                   f"{s.get('service', '') or '-'}   weak: {len(s.get('weak', []))}")
        if s.get("grades"):
            out.append(f"  cipher notları: {s['grades']}")
        trs = by_target.get(s["target"], [])
        if not trs:
            out.append("  (sonuç yok)")
            continue
        protocols = list(dict.fromkeys(r["protocol"] for r in trs))
        for proto in protocols:
            out.append(f"  [{PROTOCOL_LABELS.get(proto, proto)}]")
            prs = [r for r in trs if r["protocol"] == proto]
            if proto == "SSH":
                for cat in dict.fromkeys(r["category"] for r in prs):
                    items = [r["algorithm"] + (" [ZAYIF]" if r["weak"] else "")
                             for r in prs if r["category"] == cat]
                    out.append(f"    {CATEGORY_LABELS.get(cat, cat)}:")
                    out.extend(f"      - {i}" for i in items)
                continue
            if proto == "TLS":
                versions = list(dict.fromkeys(r["version"] for r in prs if r["version"]))
                for v in versions:
                    vr = [r for r in prs if r["version"] == v]
                    head = next((r for r in vr if r["category"] == "version"), None)
                    pref = f" (cipher tercihi: {head['detail']})" if head and head["detail"] else ""
                    out.append(f"    {v}{pref}{_mark(head) if head else ''}")
                    for r in vr:
                        if r["category"] == "version":
                            continue
                        label = "" if r["category"] == "cipher" else \
                            CATEGORY_LABELS.get(r["category"], r["category"]) + ": "
                        detail = f"  ({r['detail']})" if r["detail"] else ""
                        grade = f"  [{r['grade']}]" if r.get("grade") else ""
                        out.append(f"      - {label}{r['algorithm']}{grade}{detail}{_mark(r)}")
                rest = [r for r in prs if not r["version"]]
            else:
                rest = prs
            for r in rest:
                label = CATEGORY_LABELS.get(r["category"], r["category"])
                if r["version"]:
                    label = f"{r['version']} {label}"
                detail = f"  ({r['detail']})" if r["detail"] else ""
                out.append(f"    {label}: {r['algorithm']}{detail}{_mark(r)}")
    out.append("=" * 78)
    return "\n".join(out)


def run_scans(targets, threads, timeout, engine, conn_timeout, label="", jitter=0.0):
    """targets listesini paralel tarar; (rows, summaries) döner."""
    import random
    import time
    rows_all, summaries = [], []
    order = list(targets)
    if jitter:
        random.shuffle(order)  # sabit sıra yerine karışık: hız sınırlayıcıları tetiklememek için

    def one(h, p):
        if jitter:
            time.sleep(random.uniform(0, jitter))  # her bağlantıdan önce rastgele kısa bekleme
        return scan(h, p, timeout, engine, conn_timeout)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(one, h, p): (h, p) for h, p in order}
        for i, fut in enumerate(as_completed(futs), 1):
            h, p = futs[fut]
            try:
                rows, summ = fut.result()
            except Exception as e:
                t = f"[{h}]:{p}" if ":" in h else f"{h}:{p}"
                rows, summ = [], {"target": t, "host": h, "port": p, "state": f"error: {e}"}
            rows_all.extend(rows)
            summaries.append(summ)
            vers = ",".join(summ.get("tls_versions", [])) or ("SSH" if summ.get("ssh") else
                                                              "RDP" if summ.get("rdp") else "-")
            print(f"[{label}{i}/{len(order)}] {summ['target']:<25} {summ.get('state',''):<9} "
                  f"{vers}  weak={len(summ.get('weak', []))}", file=sys.stderr)
    return rows_all, summaries


def incomplete(summ):
    """Yeniden taranması mantıklı hedef mi? (ulaşılamayan ya da yarım kalan sonuç)"""
    state = summ.get("state", "")
    if state != "open" and not state.startswith("open"):
        return True  # filtered, timeout, error, closed
    # Açık ama hiçbir şey çıkaramadıysak (TLS/SSH/RDP bulunamadı): muhtemelen kesildi
    return not (summ.get("tls_versions") or summ.get("ssh") or summ.get("rdp"))


def main():
    for stream in (sys.stdout, sys.stderr):  # Windows konsolunda Türkçe karakterler
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:
            pass
    ap = argparse.ArgumentParser(description="ip:port listesinden TLS/SSH/RDP algoritma taraması")
    ap.add_argument("-i", "--input", required=True, help="ip:port listesi")
    ap.add_argument("-o", "--output", default="tls_results.csv", help="detay CSV")
    ap.add_argument("-s", "--summary", default="tls_summary.csv", help="hedef başına özet CSV")
    ap.add_argument("-j", "--json", help="ham sonuçları JSON olarak da yaz")
    ap.add_argument("-r", "--report", default="tls_report.txt",
                    help="okunabilir metin raporu (sürüm + algoritmalar)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="raporu ekrana yazdırma (sadece dosyaya yaz)")
    ap.add_argument("-e", "--extra", default="tls_algorithms.csv",
                    help="sade çıktı: target, state, service, tls_version, algorithm "
                         "(her algoritma bir satır)")
    ap.add_argument("-t", "--threads", type=int, default=8, help="paralel nmap sayısı")
    ap.add_argument("--timeout", type=int, default=120, help="script timeout (sn)")
    ap.add_argument("--engine", choices=["auto", "nmap", "python"], default="auto",
                    help="tarama motoru: auto = nmap varsa nmap, yoksa saf Python")
    ap.add_argument("--conn-timeout", type=int, default=5,
                    help="python motoru: bağlantı/okuma timeout'u (sn)")
    ap.add_argument("--verify", action="store_true",
                    help="zayıf TLS/CERT/DH bulgusu olan hedefleri sslscan ile doğrula")
    ap.add_argument("--verify-threads", type=int, default=4, help="paralel sslscan sayısı")
    ap.add_argument("--retry", type=int, default=0, metavar="N",
                    help="ulaşılamayan/yarım kalan hedefleri N kez daha, yavaş modda tekrar tara")
    ap.add_argument("--retry-threads", type=int, default=2,
                    help="yeniden taramada paralel sayısı (varsayılan 2, düşük tutun)")
    ap.add_argument("--retry-wait", type=int, default=30, metavar="SN",
                    help="her yeniden tarama turundan önce beklenecek süre (sn)")
    args = ap.parse_args()

    engine = args.engine
    if engine == "auto":
        engine = "nmap" if shutil.which("nmap") else "python"
    elif engine == "nmap" and not shutil.which("nmap"):
        sys.exit("[!] nmap bulunamadı. --engine python kullanın.")

    with open(args.input, encoding="utf-8-sig") as f:
        targets = [t for t in (parse_target(l) for l in f) if t]
    targets = list(dict.fromkeys(targets))  # tekrarları at
    print(f"[*] {len(targets)} hedef taranacak ({args.threads} paralel, motor: {engine})",
          file=sys.stderr)

    import time
    all_rows, summaries = run_scans(targets, args.threads, args.timeout, engine,
                                    args.conn_timeout)
    by_t = {s["target"]: s for s in summaries}

    # Ulaşılamayan / yarım kalan hedefleri yavaş modda tekrar tara
    for rnd in range(1, args.retry + 1):
        retry_targets = [(s["host"], s["port"]) for s in summaries
                         if incomplete(s) and "host" in s]
        if not retry_targets:
            print("[*] Yeniden taranacak hedef kalmadı", file=sys.stderr)
            break
        ct = args.conn_timeout + 5 * rnd  # her turda daha uzun bekle
        print(f"[*] Yeniden tarama turu {rnd}/{args.retry}: {len(retry_targets)} hedef, "
              f"{args.retry_wait} sn bekleniyor (yavaş mod: {args.retry_threads} paralel, "
              f"timeout {ct} sn)", file=sys.stderr)
        time.sleep(args.retry_wait)
        r_rows, r_summ = run_scans(retry_targets, args.retry_threads, args.timeout, engine,
                                   ct, label=f"R{rnd} ", jitter=2.0)
        # Daha iyi bir sonuç geldiyse eskisinin yerine koy
        for s in r_summ:
            old = by_t.get(s["target"])
            if old is None:
                continue
            if not incomplete(s) or (incomplete(old) and len(s.get("weak", [])) >=
                                     len(old.get("weak", []))):
                all_rows = [r for r in all_rows if r["target"] != s["target"]]
                all_rows.extend([r for r in r_rows if r["target"] == s["target"]])
                summaries[summaries.index(old)] = s
                by_t[s["target"]] = s

    if args.verify:
        if not shutil.which("sslscan"):
            print("[!] sslscan bulunamadı, doğrulama atlandı", file=sys.stderr)
        else:
            by_target = {}
            for r in all_rows:
                by_target.setdefault(r["target"], []).append(r)
            todo = [s for s in summaries if needs_verify(s, by_target.get(s["target"], []))]
            print(f"[*] sslscan doğrulaması: {len(todo)} hedef", file=sys.stderr)
            with ThreadPoolExecutor(max_workers=args.verify_threads) as ex:
                futs = {ex.submit(verify_target, s, by_target[s["target"]], args.timeout): s
                        for s in todo}
                for i, fut in enumerate(as_completed(futs), 1):
                    s = futs[fut]
                    try:
                        all_rows.extend(fut.result())
                    except Exception as e:
                        s["sslscan"] = {"status": f"error: {e}"}
                    v = s.get("sslscan", {})
                    print(f"[v {i}/{len(todo)}] {s['target']:<25} {v.get('status')} "
                          f"confirmed={v.get('confirmed', '-')}", file=sys.stderr)

    # Kademeli notlandırma: TLS cipher'larına grade ver, zayıf tiyerleri weak=YES yap
    from collections import Counter
    for r in all_rows:
        if r.get("protocol") == "TLS" and r.get("category") == "cipher":
            g = classify_cipher(r["algorithm"])
            r["grade"] = g
            r["weak"] = "YES" if g in GRADE_WEAK else ""
        else:
            r.setdefault("grade", "")
    # weak listelerini ve grade sayılarını satırlardan yeniden hesapla (tutarlılık için)
    rows_by_t = {}
    for r in all_rows:
        rows_by_t.setdefault(r["target"], []).append(r)
    for s in summaries:
        rws = rows_by_t.get(s["target"], [])
        s["weak"] = [f"{r['version'] or r['protocol']}:{r['algorithm']}"
                     for r in rws if r["weak"] == "YES"]
        gc = Counter(r["grade"] for r in rws if r.get("grade"))
        s["grades"] = " ".join(f"{g}={gc[g]}" for g in GRADE_ORDER if gc.get(g))

    all_rows.sort(key=lambda r: r["target"])
    with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(all_rows)

    with open(args.summary, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["target", "state", "service", "tls_versions", "cert_cn", "cert_issuer",
                    "cert_key", "cert_sig", "cert_not_after", "cert_expired",
                    "cert_self_signed", "dh_issues", "ssh", "rdp", "sslscan_status",
                    "sslscan_confirmed", "heartbleed", "insecure_reneg", "fallback_scsv",
                    "kex_groups", "grade_counts", "weak_count", "weak_items"])
        for s in sorted(summaries, key=lambda s: s["target"]):
            c, v = s.get("cert", {}), dict(s.get("sslscan", {}))
            # Python motorunun kendi bulguları; sslscan sonucu varsa o öncelikli
            for k, val in s.get("tls_extra", {}).items():
                v.setdefault(k, val)
            w.writerow([s["target"], s.get("state", ""), s.get("service", ""),
                        " ".join(s.get("tls_versions", [])), c.get("cn", ""),
                        c.get("issuer", ""), c.get("key", ""), c.get("sig", ""),
                        c.get("not_after", ""), c.get("expired", ""),
                        c.get("self_signed", ""), " | ".join(s.get("dh", [])),
                        s.get("ssh", ""), s.get("rdp", ""), v.get("status", ""),
                        v.get("confirmed", ""), v.get("heartbleed", ""),
                        v.get("reneg_insecure", ""), v.get("fallback_scsv", ""),
                        " ".join(v.get("groups", [])), s.get("grades", ""),
                        len(s.get("weak", [])), " | ".join(s.get("weak", []))])

    # Sade çıktı: target, state, service, tls_version, algorithm (her algoritma bir satır)
    # Sadece gerçek algoritmalar: TLS cipher'ları/kex grupları ve SSH algoritmaları.
    ALG_CATS = {"cipher", "kex-group", "kex_algorithms", "server_host_key_algorithms",
                "encryption_algorithms", "mac_algorithms", "compression_algorithms"}
    state_of = {s["target"]: s.get("state", "") for s in summaries}
    with open(args.extra, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["target", "state", "service", "tls_version", "algorithm"])
        for r in all_rows:
            if r["category"] in ALG_CATS:
                w.writerow([r["target"], state_of.get(r["target"], ""), r["service"],
                            r["version"], r["algorithm"]])

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"summary": summaries, "rows": all_rows}, f, indent=2,
                      ensure_ascii=False)

    report = build_report(summaries, all_rows)
    with open(args.report, "w", encoding="utf-8-sig") as f:
        f.write(report + "\n")
    if not args.quiet:
        print(report)

    print(f"[+] Sade: {args.extra}  Rapor: {args.report}  Detay: {args.output}  "
          f"Özet: {args.summary}", file=sys.stderr)


if __name__ == "__main__":
    main()
