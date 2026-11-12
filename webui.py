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

import time
from datetime import datetime

import tlsscan

HERE = os.path.dirname(os.path.abspath(__file__))
HISTORY_DIR = os.path.join(HERE, "webui_history")

# --------------------------------------------------------------------------
# Tarama durumu (tek seferde bir tarama)
# --------------------------------------------------------------------------
LOCK = threading.Lock()
STOP = threading.Event()
STATE = {
    "running": False, "done": False, "error": "", "stopped": False,
    "total": 0, "completed": 0, "engine": "", "phase": "",
    "progress": [],       # [{i,target,state,versions,weak}]
    "rows": [], "summaries": [],
    "started": "", "params": {},
}


def reset_state():
    STOP.clear()
    with LOCK:
        STATE.update({"running": True, "done": False, "error": "", "stopped": False,
                      "total": 0, "completed": 0, "progress": [], "phase": "",
                      "rows": [], "summaries": []})


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

        counter = {"n": 0}

        def on_progress(i, total, summ):
            vers = ",".join(summ.get("tls_versions", [])) or (
                "SSH" if summ.get("ssh") else "RDP" if summ.get("rdp") else "-")
            with LOCK:
                counter["n"] += 1
                STATE["completed"] = counter["n"]
                STATE["progress"].append({
                    "i": counter["n"], "target": summ.get("target", ""),
                    "state": summ.get("state", ""), "versions": vers,
                    "weak": len(summ.get("weak", []))})

        rows, summaries = tlsscan.run_scans(
            targets, params["threads"], 120, engine, params["conn_timeout"],
            progress=on_progress, stop_event=STOP)

        # Yeniden tarama turları (ulaşılamayan / yarım kalan hedefler)
        by_t = {s["target"]: s for s in summaries}
        for rnd in range(1, params.get("retry", 0) + 1):
            if STOP.is_set():
                break
            retry_targets = [(s["host"], s["port"]) for s in summaries
                             if tlsscan.incomplete(s) and "host" in s]
            if not retry_targets:
                break
            with LOCK:
                STATE["phase"] = (f"yeniden tarama turu {rnd}/{params['retry']} "
                                  f"({len(retry_targets)} hedef, bekleniyor…)")
                STATE["total"] += len(retry_targets)
            waited = 0
            while waited < params.get("retry_wait", 30) and not STOP.is_set():
                time.sleep(0.5)
                waited += 0.5
            if STOP.is_set():
                break
            with LOCK:
                STATE["phase"] = f"yeniden tarama turu {rnd}/{params['retry']}"
            ct = params["conn_timeout"] + 5 * rnd
            r_rows, r_summ = tlsscan.run_scans(
                retry_targets, params.get("retry_threads", 2), 120, engine, ct,
                label=f"R{rnd} ", jitter=2.0, progress=on_progress, stop_event=STOP)
            for s in r_summ:
                old = by_t.get(s["target"])
                if old is None:
                    continue
                better = (not tlsscan.incomplete(s)) or (
                    tlsscan.incomplete(old) and
                    len(s.get("weak", [])) >= len(old.get("weak", [])))
                if better:
                    rows = [r for r in rows if r["target"] != s["target"]]
                    rows.extend([r for r in r_rows if r["target"] == s["target"]])
                    summaries[summaries.index(old)] = s
                    by_t[s["target"]] = s

        # İsteğe bağlı sslscan doğrulaması
        if params.get("verify") and shutil.which("sslscan") and not STOP.is_set():
            with LOCK:
                STATE["phase"] = "sslscan doğrulaması"
            bt = {}
            for r in rows:
                bt.setdefault(r["target"], []).append(r)
            todo = [s for s in summaries
                    if tlsscan.needs_verify(s, bt.get(s["target"], []))]
            for s in todo:
                if STOP.is_set():
                    break
                try:
                    rows.extend(tlsscan.verify_target(s, bt[s["target"]], 120))
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
            STATE["stopped"] = STOP.is_set()
            STATE["phase"] = ""
        save_history(params, summaries, rows)
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


def build_txt():
    with LOCK:
        return tlsscan.build_report(STATE["summaries"], STATE["rows"])


def build_json():
    with LOCK:
        return json.dumps({"summaries": STATE["summaries"], "rows": STATE["rows"]},
                          ensure_ascii=False, indent=2)


def build_xlsx():
    with LOCK:
        return tlsscan.xlsx_bytes(STATE["summaries"], STATE["rows"])


# --------------------------------------------------------------------------
# Geçmiş taramalar (yerel diske JSON olarak kaydedilir)
# --------------------------------------------------------------------------
def save_history(params, summaries, rows):
    try:
        os.makedirs(HISTORY_DIR, exist_ok=True)
        hid = datetime.now().strftime("%Y%m%d-%H%M%S")
        # hedef listesini kaydetmeye gerek yok; sadece özet+satırlar
        safe_params = {k: params.get(k) for k in
                       ("engine", "threads", "conn_timeout", "verify", "retry")}
        nweak = sum(1 for s in summaries if s.get("weak"))
        rec = {"id": hid, "time": datetime.now().isoformat(timespec="seconds"),
               "params": safe_params, "n_targets": len(summaries), "n_weak": nweak,
               "summaries": summaries, "rows": rows}
        with open(os.path.join(HISTORY_DIR, hid + ".json"), "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False)
    except Exception:
        pass  # geçmiş kaydı başarısız olsa da tarama sonucu etkilenmesin


def list_history():
    out = []
    if not os.path.isdir(HISTORY_DIR):
        return out
    for fn in sorted(os.listdir(HISTORY_DIR), reverse=True):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(HISTORY_DIR, fn), encoding="utf-8") as f:
                d = json.load(f)
            out.append({"id": d["id"], "time": d.get("time", ""),
                        "n_targets": d.get("n_targets", 0), "n_weak": d.get("n_weak", 0),
                        "params": d.get("params", {})})
        except Exception:
            continue
    return out


def load_history(hid):
    if not hid or "/" in hid or "\\" in hid or ".." in hid:
        return None
    p = os.path.join(HISTORY_DIR, hid + ".json")
    if not os.path.isfile(p):
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


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
                    "phase": STATE["phase"], "stopped": STATE["stopped"],
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
        elif path == "/api/export.txt":
            self._send(200, build_txt(), "text/plain; charset=utf-8",
                       {"Content-Disposition": "attachment; filename=tls_report.txt"})
        elif path == "/api/export.json":
            self._send(200, build_json(), "application/json; charset=utf-8",
                       {"Content-Disposition": "attachment; filename=tls_results.json"})
        elif path == "/api/export.xlsx":
            self._send(200, build_xlsx(),
                       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                       {"Content-Disposition": "attachment; filename=tls_results.xlsx"})
        elif path == "/api/history":
            self._json(200, {"history": list_history()})
        elif path == "/api/history/get":
            hid = (parse_qs(urlparse(self.path).query).get("id") or [""])[0]
            rec = load_history(hid)
            if rec is None:
                self._json(404, {"error": "Kayıt bulunamadı."})
                return
            with LOCK:
                if not STATE["running"]:  # dışa aktarma bu kayıttan olsun
                    STATE["rows"] = rec.get("rows", [])
                    STATE["summaries"] = rec.get("summaries", [])
            self._json(200, {"summaries": [summary_view(s) for s in rec.get("summaries", [])],
                             "rows": rec.get("rows", [])})
        else:
            self._send(404, "bulunamadı", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/stop":
            STOP.set()
            self._json(200, {"ok": True})
            return
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
            "retry": max(0, min(int(data.get("retry", 0) or 0), 5)),
            "retry_wait": max(0, min(int(data.get("retry_wait", 30) or 30), 600)),
            "retry_threads": 2,
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
