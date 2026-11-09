#!/usr/bin/env python3
"""
tlsscan için yerel web arayüzü. Sadece Python standart kütüphanesi (ek kurulum yok).

Çalıştırma:
    python webui.py            # http://127.0.0.1:8765 açılır
    python webui.py --port 9000 --no-browser

Tarayıcıda hedefleri girip tarama başlatırsın; ilerleme canlı güncellenir,
sonuçlar grade (Güçlü/Orta/Zayıf...) renkleriyle, filtrelenebilir tabloda görünür.
Güvenlik: sunucu yalnızca 127.0.0.1'e bağlanır (dışarıya açık değildir).
"""
import argparse
import csv
import io
import json
import os
import shutil
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import tlsscan

HERE = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------
# Tarama durumu (tek seferde bir tarama)
# --------------------------------------------------------------------------
LOCK = threading.Lock()
STATE = {
    "running": False, "done": False, "error": "",
    "total": 0, "completed": 0, "engine": "",
    "progress": [],       # [{i,target,state,versions,weak}]
    "rows": [], "summaries": [],
    "started": "", "params": {},
}


def reset_state():
    with LOCK:
        STATE.update({"running": True, "done": False, "error": "", "total": 0,
                      "completed": 0, "progress": [], "rows": [], "summaries": []})


def scan_worker(params):
    try:
        targets = []
        for line in params["targets"].splitlines():
            t = tlsscan.parse_target(line)
            if t:
                targets.append(t)
        targets = list(dict.fromkeys(targets))
        if not targets:
            with LOCK:
                STATE["error"] = "Geçerli hedef bulunamadı (ip:port biçiminde girin)."
                STATE["running"] = False
            return

        engine = params["engine"]
        if engine == "auto":
            engine = "nmap" if shutil.which("nmap") else "python"
        with LOCK:
            STATE["total"] = len(targets)
            STATE["engine"] = engine

        def on_progress(i, total, summ):
            vers = ",".join(summ.get("tls_versions", [])) or (
                "SSH" if summ.get("ssh") else "RDP" if summ.get("rdp") else "-")
            with LOCK:
                STATE["completed"] = i
                STATE["progress"].append({
                    "i": i, "target": summ.get("target", ""),
                    "state": summ.get("state", ""), "versions": vers,
                    "weak": len(summ.get("weak", []))})

        rows, summaries = tlsscan.run_scans(
            targets, params["threads"], 120, engine, params["conn_timeout"],
            progress=on_progress)

        # İsteğe bağlı sslscan doğrulaması
        if params.get("verify") and shutil.which("sslscan"):
            by_t = {}
            for r in rows:
                by_t.setdefault(r["target"], []).append(r)
            todo = [s for s in summaries
                    if tlsscan.needs_verify(s, by_t.get(s["target"], []))]
            for s in todo:
                try:
                    rows.extend(tlsscan.verify_target(s, by_t[s["target"]], 120))
                except Exception as e:
                    s["sslscan"] = {"status": f"error: {e}"}

        tlsscan.finalize_grades(rows, summaries)
        rows.sort(key=lambda r: r["target"])
        summaries.sort(key=lambda s: s["target"])

        with LOCK:
            STATE["rows"] = rows
            STATE["summaries"] = summaries
            STATE["running"] = False
            STATE["done"] = True
    except Exception as e:
        with LOCK:
            STATE["error"] = f"{type(e).__name__}: {e}"
            STATE["running"] = False


def summary_view(s):
    """Özet sözlüğünü arayüz için sadeleştir."""
    c = s.get("cert", {})
    v = dict(s.get("sslscan", {}))
    for k, val in s.get("tls_extra", {}).items():
        v.setdefault(k, val)
    return {
        "target": s.get("target", ""), "state": s.get("state", ""),
        "service": s.get("service", ""),
        "tls_versions": s.get("tls_versions", []),
        "ssh": bool(s.get("ssh")), "rdp": bool(s.get("rdp")),
        "cert": {"cn": c.get("cn", ""), "issuer": c.get("issuer", ""),
                 "key": c.get("key", ""), "sig": c.get("sig", ""),
                 "not_after": c.get("not_after", ""), "expired": c.get("expired", ""),
                 "self_signed": c.get("self_signed", "")},
        "dh": s.get("dh", []),
        "sslscan": {"status": v.get("status", ""), "confirmed": v.get("confirmed", ""),
                    "heartbleed": v.get("heartbleed", ""),
                    "reneg_insecure": v.get("reneg_insecure", ""),
                    "fallback_scsv": v.get("fallback_scsv", ""),
                    "groups": v.get("groups", [])},
        "grade_counts": s.get("grade_counts", {}),
        "weak_count": len(s.get("weak", [])), "weak_items": s.get("weak", []),
    }


def build_csv():
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=tlsscan.FIELDS)
    w.writeheader()
    with LOCK:
        for r in STATE["rows"]:
            w.writerow({k: r.get(k, "") for k in tlsscan.FIELDS})
    return out.getvalue()


# --------------------------------------------------------------------------
# HTTP sunucu
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # sessiz

    def _send(self, code, body, ctype="application/json; charset=utf-8",
              extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, val in (extra or {}).items():
            self.send_header(k, val)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), extra=None)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(HERE, "webui.html"), encoding="utf-8") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(500, "webui.html bulunamadı (webui.py ile aynı klasörde olmalı)",
                           "text/plain; charset=utf-8")
        elif path == "/api/status":
            with LOCK:
                self._json(200, {
                    "running": STATE["running"], "done": STATE["done"],
                    "error": STATE["error"], "total": STATE["total"],
                    "completed": STATE["completed"], "engine": STATE["engine"],
                    "progress": STATE["progress"][-200:]})
        elif path == "/api/results":
            with LOCK:
                summ = [summary_view(s) for s in STATE["summaries"]]
                rows = STATE["rows"]
            self._json(200, {"summaries": summ, "rows": rows})
        elif path == "/api/tools":
            self._json(200, {"nmap": bool(shutil.which("nmap")),
                             "sslscan": bool(shutil.which("sslscan"))})
        elif path == "/api/export.csv":
            self._send(200, build_csv(), "text/csv; charset=utf-8",
                       {"Content-Disposition": "attachment; filename=tls_results.csv"})
        else:
            self._send(404, "bulunamadı", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/scan":
            self._send(404, "bulunamadı", "text/plain; charset=utf-8")
            return
        with LOCK:
            if STATE["running"]:
                self._json(409, {"error": "Zaten bir tarama çalışıyor."})
                return
        try:
            ln = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(ln) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "Geçersiz istek."})
            return
        params = {
            "targets": str(data.get("targets", "")),
            "engine": data.get("engine", "auto"),
            "threads": max(1, min(int(data.get("threads", 8) or 8), 64)),
            "conn_timeout": max(1, min(int(data.get("conn_timeout", 5) or 5), 60)),
            "verify": bool(data.get("verify", False)),
        }
        reset_state()
        with LOCK:
            STATE["params"] = params
        threading.Thread(target=scan_worker, args=(params,), daemon=True).start()
        self._json(200, {"ok": True})


def main():
    ap = argparse.ArgumentParser(description="tlsscan yerel web arayüzü")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1",
                    help="varsayılan 127.0.0.1 (yalnız yerel). Dikkatli değiştirin.")
    ap.add_argument("--no-browser", action="store_true", help="tarayıcıyı otomatik açma")
    args = ap.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"[*] tlsscan web arayüzü: {url}")
    print("    (durdurmak için Ctrl+C)")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] kapatılıyor")
        srv.shutdown()


if __name__ == "__main__":
    main()
