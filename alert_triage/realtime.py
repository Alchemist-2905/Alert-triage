"""Real-time engine: tails alert files (JSONL / Suricata eve.json / Wazuh alerts.json) and/or accepts
HTTP POSTs, scores every micro-batch against a rolling context window and stores the results."""
from __future__ import annotations

import json
import queue
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pandas as pd

from .ingest import records_to_frame
from .pipeline import ModelBundle, score
from .preprocess import preprocess
from .store import Store


class FileTailer(threading.Thread):
    """`tail -f` for JSON-lines files (handles rotation/truncation and partial lines)."""

    def __init__(self, path: str | Path, out: "queue.Queue[dict]", from_start: bool = False, poll: float = 0.5):
        super().__init__(daemon=True)
        self.path, self.out, self.poll, self.from_start = Path(path), out, poll, from_start
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        pos, buf, first = 0, "", True
        while not self._stop.is_set():
            try:
                if not self.path.exists():
                    time.sleep(self.poll)
                    continue
                size = self.path.stat().st_size
                if first:
                    pos = 0 if self.from_start else size
                    first = False
                if size < pos:  # truncated / rotated
                    pos, buf = 0, ""
                if size > pos:
                    with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(pos)
                        chunk = fh.read()
                        pos = fh.tell()
                    buf += chunk
                    *lines, buf = buf.split("\n")
                    for ln in lines:
                        ln = ln.strip()
                        if ln:
                            try:
                                self.out.put(json.loads(ln))
                            except json.JSONDecodeError:
                                pass
            except OSError:
                pass
            time.sleep(self.poll)


def start_http_ingest(port: int, out: "queue.Queue[dict]", host: str = "0.0.0.0") -> ThreadingHTTPServer:
    """POST /alert with a JSON object or array; GET /health."""

    class H(BaseHTTPRequestHandler):
        def _send(self, code, payload):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._send(200, {"status": "ok", "queued": out.qsize()})

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(n) or b"{}")
                items = data if isinstance(data, list) else [data]
                for it in items:
                    if isinstance(it, dict):
                        out.put(it)
                self._send(202, {"accepted": len(items)})
            except Exception as exc:  # malformed input must not kill the server
                self._send(400, {"error": str(exc)})

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class LiveEngine:
    """Keeps a rolling buffer so temporal/provenance context works on streaming data."""

    def __init__(self, bundle: ModelBundle, store: Store):
        self.bundle, self.store = bundle, store
        self.live_cfg = bundle.cfg["live"]
        self.buffer = pd.DataFrame()
        self.total = 0

    def process(self, records: list[dict]) -> pd.DataFrame:
        """Score a micro-batch of raw records; returns the newly scored alerts."""
        new, _ = preprocess(records_to_frame(records))
        if new.empty:
            return new
        self.buffer = pd.concat([self.buffer, new], ignore_index=True) if len(self.buffer) else new
        self.buffer = self.buffer.drop_duplicates("alert_id", keep="last")
        # ignore clock-skewed "future" timestamps when sliding the window
        latest = min(self.buffer["timestamp"].max(), pd.Timestamp.now("UTC").tz_localize(None) + pd.Timedelta(minutes=10))
        cutoff = latest - pd.Timedelta(minutes=self.live_cfg["window_minutes"])
        self.buffer = self.buffer[self.buffer["timestamp"] >= cutoff].tail(self.live_cfg["max_buffer"])
        self.buffer = self.buffer.sort_values("timestamp", kind="stable").reset_index(drop=True)
        scored = score(self.buffer, self.bundle, already_clean=True)
        fresh = scored[scored["alert_id"].isin(set(new["alert_id"]))]
        self.store.write(fresh)
        self.total += len(fresh)
        return fresh


def run_live(bundle: ModelBundle, db_path: str, watch: list[str], http_port: int | None,
             from_start: bool = False, alert_log: str = "output/high_priority_alerts.log",
             simulate_feed: bool = False):
    q: "queue.Queue[dict]" = queue.Queue()
    store = Store(db_path)
    engine = LiveEngine(bundle, store)
    tailers = [FileTailer(p, q, from_start=from_start) for p in watch]
    for t in tailers:
        t.start()
    srv = start_http_ingest(http_port, q) if http_port else None
    
    if simulate_feed:
        from .data_gen import LiveGenerator
        def _sim_worker():
            gen = LiveGenerator(campaign_every_s=25, scanner_every_s=50)
            while True:
                time.sleep(1.0)
                now = datetime.now()
                for rec in gen.tick(now, rate=2.5):
                    q.put(rec)
        threading.Thread(target=_sim_worker, daemon=True).start()
        print("[live] internal real-time event simulator active (~2-3 alerts/sec with attack campaigns)")

    Path(alert_log).parent.mkdir(parents=True, exist_ok=True)
    interval, max_batch = engine.live_cfg["batch_interval"], engine.live_cfg["max_batch"]
    print(f"[live] watching {watch or '-'} | HTTP port {http_port or '-'} | DB {db_path} | simulate={simulate_feed}")
    print("[live] Ctrl+C to stop. Open the dashboard:  python main.py dashboard")
    try:
        while True:
            batch = []
            while len(batch) < max_batch:
                try:
                    batch.append(q.get_nowait())
                except queue.Empty:
                    break
            if batch:
                t0 = time.time()
                fresh = engine.process(batch)
                hi = fresh[(fresh["priority"].isin(["High", "Critical"])) & (fresh["is_duplicate"] == 0)]
                print(f"[{datetime.now():%H:%M:%S}] {len(batch):4d} alerts scored in {time.time() - t0:4.2f}s | "
                      f"High/Critical: {len(hi)} | total {engine.total:,}")
                if len(hi):
                    with open(alert_log, "a", encoding="utf-8") as fh:
                        for r in hi.itertuples():
                            line = (f"{r.timestamp} [{r.priority.upper()}] risk={r.risk_score:.1f} "
                                    f"{r.src_ip} -> {r.dst_ip} | {r.signature} | {r.rule_hits}")
                            print("   !!", line)
                            fh.write(line + "\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[live] stopping")
    finally:
        for t in tailers:
            t.stop()
        if srv:
            srv.shutdown()
        store.close()
