import json

from pingo.app_log import AppLog


def test_logs_survive_restart_and_exclude_private_payloads(tmp_path):
    log = AppLog(tmp_path / "logs")
    log.write({"event": "message", "text": "secret message", "key": "secret key"})
    log.write({"event": "traffic", "wire_hex": "secret packet"})
    log.write({"event": "progress", "name": "private.txt"})
    log.write({"event": "log", "level": "error", "text": "peer did not authenticate"})
    restored = AppLog(log.root).read()
    assert len(restored["records"]) == 2
    assert restored["records"][-1]["level"] == "error"
    assert "secret" not in log.path.read_text()
    assert "private.txt" not in log.path.read_text()


def test_rotation_is_bounded_and_records_are_chronological(tmp_path):
    log = AppLog(tmp_path / "logs", max_bytes=250, backups=2)
    for code in range(40):
        log.write({"event": "finished", "code": code})
    assert len(list(log.root.iterdir())) == 3
    records = log.read()["records"]
    codes = [r["code"] for r in records]
    assert codes == sorted(codes) and codes[-1] == 39 and len(codes) < 40
    assert all(p.stat().st_size <= 250 for p in log.root.iterdir())


def test_partial_record_is_ignored_and_read_is_limited(tmp_path):
    log = AppLog(tmp_path / "logs")
    for code in range(8):
        log.write({"event": "finished", "code": code})
    with log.path.open("a") as stream:
        stream.write('{"incomplete"')
    assert [r["code"] for r in log.read(limit=3)["records"]] == [5, 6, 7]
    log.write({"event": "finished", "code": 8})
    assert log.read()["records"][-1]["code"] == 8


def test_logging_failure_is_reported_without_crashing(tmp_path):
    log = AppLog(tmp_path / "logs")
    log.path.mkdir()
    log.write({"event": "app_started"})
    assert log.error


def test_long_diagnostics_are_bounded(tmp_path):
    log = AppLog(tmp_path / "logs")
    log.write({"event": "error", "text": "x" * 100000})
    assert len(json.loads(log.path.read_text())["text"]) == 4096
