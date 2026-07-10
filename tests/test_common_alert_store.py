"""Tests for tools._common.alert_store.AlertStore."""

from tools._common.alert_store import AlertStore


def _alert(sev="HIGH", cat="MITM", title="Gateway MAC changed", details=None):
    d = {
        "_count": 1,
        "_first_seen_ts": "2026-07-10 12:00:00",
        "_last_seen_ts": "2026-07-10 12:00:00",
    }
    if details:
        d.update(details)
    return {
        "timestamp": "2026-07-10 12:00:00",
        "severity": sev,
        "category": cat,
        "title": title,
        "details": d,
    }


def test_insert_and_count(tmp_path):
    s = AlertStore(str(tmp_path / "a.db"))
    rid = s.insert(_alert(), ts_epoch=1000.0)
    assert isinstance(rid, int) and rid > 0
    assert s.count() == 1


def test_round_trip_load(tmp_path):
    s = AlertStore(str(tmp_path / "a.db"))
    s.insert(_alert(title="T1"), ts_epoch=1000.0)
    rows = s.load()
    assert len(rows) == 1
    a = rows[0]
    assert a["severity"] == "HIGH"
    assert a["category"] == "MITM"
    assert a["title"] == "T1"
    assert a["details"]["_count"] == 1
    assert a["_db_id"] > 0
    assert a["_ts_epoch"] == 1000.0


def test_persists_across_instances(tmp_path):
    # The core guarantee: threat history survives closing the app.
    path = str(tmp_path / "a.db")
    s1 = AlertStore(path)
    s1.insert(_alert(title="survives"), ts_epoch=1000.0)
    del s1
    s2 = AlertStore(path)  # simulates reopening the app
    rows = s2.load()
    assert len(rows) == 1
    assert rows[0]["title"] == "survives"


def test_filters_and_ordering(tmp_path):
    s = AlertStore(str(tmp_path / "a.db"))
    s.insert(_alert(sev="HIGH", cat="MITM", title="h1"), ts_epoch=1000.0)
    s.insert(_alert(sev="INFO", cat="DEVICE", title="i1"), ts_epoch=2000.0)
    s.insert(_alert(sev="HIGH", cat="SCAN", title="h2"), ts_epoch=3000.0)
    assert len(s.load(severity="HIGH")) == 2
    assert len(s.load(category="DEVICE")) == 1
    assert len(s.load(since_epoch=1500.0)) == 2
    assert len(s.load(until_epoch=1500.0)) == 1
    assert len(s.load(since_epoch=1500.0, until_epoch=2500.0)) == 1
    # newest-first ordering by epoch
    assert [r["title"] for r in s.load()] == ["h2", "i1", "h1"]


def test_load_limit(tmp_path):
    s = AlertStore(str(tmp_path / "a.db"))
    for i in range(5):
        s.insert(_alert(title=f"t{i}"), ts_epoch=1000.0 + i)
    assert len(s.load(limit=3)) == 3


def test_update_seen(tmp_path):
    s = AlertStore(str(tmp_path / "a.db"))
    rid = s.insert(_alert(title="dup"), ts_epoch=1000.0)
    s.update_seen(rid, count=5, last_seen="2026-07-10 12:05:00")
    row = s.load()[0]
    assert row["details"]["_count"] == 5
    assert row["details"]["_last_seen_ts"] == "2026-07-10 12:05:00"


def test_prune_older_than(tmp_path):
    s = AlertStore(str(tmp_path / "a.db"))
    s.insert(_alert(title="old"), ts_epoch=1000.0)
    s.insert(_alert(title="new"), ts_epoch=5000.0)
    assert s.prune_older_than(3000.0) == 1
    rows = s.load()
    assert len(rows) == 1 and rows[0]["title"] == "new"


def test_bad_path_is_safe(tmp_path):
    # Parent dir doesn't exist -> every op degrades to a safe default, no raise.
    bad = str(tmp_path / "nope" / "deep" / "a.db")
    s = AlertStore(bad)
    assert s.insert(_alert()) is None
    assert s.load() == []
    assert s.count() == 0
    assert s.prune_older_than(1.0) == 0
