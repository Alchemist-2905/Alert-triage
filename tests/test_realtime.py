import json
import queue
import time

from alert_triage.data_gen import LiveGenerator
from alert_triage.realtime import FileTailer, LiveEngine, start_http_ingest
from alert_triage.store import Store
from datetime import datetime
import urllib.request


def test_store_roundtrip(bundle, test_df, tmp_path):
    from alert_triage.pipeline import score
    s = score(test_df.head(300), bundle)
    st = Store(tmp_path / "t.db")
    assert st.write(s) == len(s) and st.count() == len(s)
    st.write(s)  # idempotent upsert
    assert st.count() == len(s)
    back = st.read()
    assert {"risk_score", "priority", "reasons"} <= set(back.columns)


def test_live_engine_scores_stream_and_flags_attack(bundle, tmp_path):
    store = Store(tmp_path / "live.db")
    eng = LiveEngine(bundle, store)
    gen = LiveGenerator(seed=3, campaign_every_s=5)
    now = datetime.utcnow()
    from datetime import timedelta
    for i in range(120):
        eng.process(gen.tick(now + timedelta(seconds=i), rate=1.5))
    d = store.read()
    assert len(d) > 100 and d["alert_id"].is_unique
    mal, ben = d[d["label"] == 1], d[d["label"] == 0]
    assert len(mal) > 10 and mal["risk_score"].mean() > ben["risk_score"].mean() + 20


def test_file_tailer_and_http(tmp_path):
    q = queue.Queue()
    f = tmp_path / "feed.jsonl"
    f.write_text("")
    t = FileTailer(f, q, poll=0.1)
    t.start()
    time.sleep(0.3)
    with open(f, "a") as fh:
        fh.write(json.dumps({"a": 1}) + "\n" + json.dumps({"a": 2}) + "\n" + '{"partial"')
    srv = start_http_ingest(0, q, host="127.0.0.1")
    port = srv.server_address[1]
    req = urllib.request.Request(f"http://127.0.0.1:{port}/alert", data=json.dumps([{"b": 1}, {"b": 2}]).encode(), method="POST")
    assert json.load(urllib.request.urlopen(req))["accepted"] == 2
    time.sleep(0.6)
    t.stop(); srv.shutdown()
    got = []
    while not q.empty():
        got.append(q.get())
    assert {"a": 1} in got and {"a": 2} in got and {"b": 2} in got and len(got) == 4  # partial line ignored
