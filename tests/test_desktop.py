import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from pingo import cli
from pingo.config import Config, generate_key
from pingo.desktop import Api, Desktop, page_html
from pingo.reliable import Reliable
from pingo.resume import ResumableReceiver, send_resumable
from pingo.transport import Endpoint

from .helpers import KEY, carriers, connected


@pytest.fixture
def desktop(tmp_path, monkeypatch):
    # ACL commands are separately verified with the native desktop smoke test.
    monkeypatch.setattr("pingo.desktop.private_directory", lambda p: p.mkdir(exist_ok=True))
    monkeypatch.setattr("pingo.desktop.local_network_checks", lambda *_: [])
    return Desktop(tmp_path / "desktop")


def connection(desktop):
    key = desktop.root / "peer.key"
    generate_key(key)
    return desktop.save_profile(
        {
            "name": "Home",
            "peer": "192.0.2.20",
            "bind": "192.0.2.10",
            "key_file": str(key),
        }
    )


def test_saved_connection_survives_restart_without_exposing_key(desktop):
    p = connection(desktop)
    restored = Desktop(desktop.root)
    assert restored.selected == p["id"]
    assert restored.profiles == desktop.profiles
    config = Config.load(restored._config_path(p["id"]))
    assert config.peer == "192.0.2.20"
    assert config.key() == Path(p["key_file"]).read_bytes()
    assert config.key().hex() not in json.dumps(Api(restored).snapshot())


def test_malformed_saved_connection_still_allows_setup(desktop):
    (desktop.root / "connections.json").write_text(
        json.dumps({"profiles": {"invalid": None}, "selected": "invalid"}), encoding="utf-8"
    )
    restored = Desktop(desktop.root)
    assert restored.snapshot()["profiles"] == [] and restored.selected is None
    assert connection(restored)["peer"] == "192.0.2.20"


def test_invalid_edit_preserves_saved_connection(desktop):
    p = connection(desktop)
    original = desktop._config_path(p["id"]).read_bytes()
    for change in (
        {"peer": "hostname"},
        {"attempts": 0},
        {"id": "../outside"},
        {"kill_switch": "yes"},
        {"dns": ["::1"]},
        {"key_file": "missing.key"},
    ):
        result = Api(desktop).save_connection({**p, **change})
        assert result["ok"] is False
        assert desktop._config_path(p["id"]).read_bytes() == original
        assert desktop.profiles[p["id"]] == p


def test_failed_save_preserves_displayed_and_persisted_connection(desktop, monkeypatch):
    from pingo import desktop as module

    profile = connection(desktop)
    original = module.atomic_write

    def fail(path, text):
        if path.name == "connections.json":
            raise OSError("disk full")
        return original(path, text)

    monkeypatch.setattr(module, "atomic_write", fail)
    assert not Api(desktop).save_connection({**profile, "peer": "192.0.2.99"})["ok"]
    assert desktop.profiles[profile["id"]] == profile
    restored = Desktop(desktop.root)
    assert restored._config(restored.profiles[profile["id"]]).peer == profile["peer"]


def test_worker_uses_displayed_connection_and_stable_snapshot(desktop, tmp_path, monkeypatch):
    from pingo.desktop import config_text

    profile = connection(desktop)
    monkeypatch.setattr("pingo.desktop.elevated", lambda: True)
    atomic_cache = desktop._config_path(profile["id"])
    atomic_cache.write_text(config_text({**profile, "peer": "192.0.2.99"}), encoding="utf-8")
    result_path = tmp_path / "worker-result.json"
    script = tmp_path / "fake_worker.py"
    script.write_text(
        "import json,sys,tomllib\nfrom pathlib import Path\n"
        "argv=json.loads(sys.stdin.readline())['argv']\n"
        "path=Path(argv[argv.index('--config')+1])\n"
        "config=tomllib.loads(path.read_text())\n"
        f"Path({str(result_path)!r}).write_text(json.dumps({{'path':str(path),'peer':config['peer']}}))\n"
        "sys.stdin.readline()\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(desktop, "_worker_command", lambda: [sys.executable, str(script)])
    desktop.start(profile["id"], "listen")
    deadline = time.monotonic() + 5
    while not result_path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    result = json.loads(result_path.read_text())
    assert result["peer"] == profile["peer"]
    snapshot_path = Path(result["path"])
    assert snapshot_path != atomic_cache
    assert Config.load(snapshot_path).peer == profile["peer"]
    desktop.stop()
    desktop.monitor.join(5)
    assert desktop.process is None and not snapshot_path.exists()


def test_pairing_export_has_matching_key_and_swapped_endpoints(desktop, tmp_path):
    pytest.importorskip("webview")
    p = connection(desktop)
    desktop.window = SimpleNamespace(create_file_dialog=lambda *_a, **_k: [str(tmp_path)])
    folder = Path(Api(desktop).export_pairing(p["id"])["data"])
    other = Config.load(folder / "peer.toml")
    assert other.peer == p["bind"] and other.bind == p["peer"]
    assert other.key() == Path(p["key_file"]).read_bytes()
    assert "SECRET" in (folder / "READ-ME.txt").read_text()
    second = Path(Api(desktop).export_pairing(p["id"])["data"])
    assert second != folder and (folder / "peer.toml").exists()


def test_setup_check_labels_network_path_as_unverified(desktop, monkeypatch):
    p = connection(desktop)
    monkeypatch.setattr("pingo.desktop.elevated", lambda: False)
    checks = desktop.check(p["id"])
    assert next(c for c in checks if c["name"] == "Network permissions")["status"] == "fail"
    network = next(c for c in checks if c["name"] == "Peer and firewall")
    assert network["status"] == "manual" and "does not contact" in network["detail"]


def test_non_admin_action_fails_before_starting_worker(desktop, monkeypatch):
    p = connection(desktop)
    monkeypatch.setattr("pingo.desktop.elevated", lambda: False)
    monkeypatch.setattr(desktop, "_worker_command", lambda: pytest.fail("must not spawn"))
    result = Api(desktop).start(p["id"], "listen")
    assert not result["ok"] and "Administrator" in result["hint"]


@pytest.mark.parametrize("action", ["message", "listen", "file", "vpn", "probe"])
def test_same_endpoint_is_rejected_before_worker_start(desktop, monkeypatch, action):
    profile = connection(desktop)
    profile = desktop.save_profile({**profile, "peer": profile["bind"]})
    monkeypatch.setattr("pingo.desktop.elevated", lambda: True)
    monkeypatch.setattr(desktop, "_worker_command", lambda: pytest.fail("must not spawn"))
    response = Api(desktop).start(profile["id"], action)
    assert not response["ok"] and "same IPv4" in response["error"]


def test_vpn_overlap_rejected_before_adapter_or_worker_start(desktop, monkeypatch):
    profile = connection(desktop)
    profile = desktop.save_profile({**profile, "address": "192.0.2.9/24"})
    monkeypatch.setattr("pingo.desktop.elevated", lambda: True)
    monkeypatch.setattr(desktop, "_worker_command", lambda: pytest.fail("must not spawn"))
    response = Api(desktop).start(profile["id"], "vpn")
    assert not response["ok"] and "tunnel subnet" in response["error"]


def test_setup_checks_cannot_run_during_an_activity(desktop):
    profile = connection(desktop)
    desktop.process = object()
    response = Api(desktop).check_setup(profile["id"])
    assert not response["ok"] and "Stop the current activity" in response["error"]


def test_desktop_logs_persist_diagnostics_without_message_contents(desktop):
    desktop._event({"event": "log", "level": "warning", "text": "Peer is unavailable"})
    desktop._event({"event": "message", "text": "do not save this"})
    restored = Desktop(desktop.root)
    result = Api(restored).read_logs()["data"]
    assert any(r.get("text") == "Peer is unavailable" for r in result["records"])
    assert "do not save this" not in json.dumps(result)


def test_failed_and_reconnecting_states_have_distinct_log_severity(desktop):
    desktop._event({"event": "state", "state": "reconnecting", "reason": "no reply"})
    desktop._event({"event": "state", "state": "failed"})
    records = Api(desktop).read_logs()["data"]["records"]
    assert records[-2]["level"] == "warning" and records[-2]["reason"] == "no reply"
    assert records[-1]["level"] == "error"


def test_address_refresh_updates_snapshot_and_retains_old_rows_on_error(desktop, monkeypatch):
    rows = [{"name": "VPN", "address": "10.77.0.1", "loopback": False, "up": True}]
    monkeypatch.setattr("pingo.desktop.local_ipv4", lambda: rows)
    assert Api(desktop).refresh_addresses()["data"]["interfaces"] == rows
    snapshot = desktop.snapshot()
    assert snapshot["interfaces"] == rows and snapshot["local_addresses"] == ["10.77.0.1"]

    def failed():
        raise OSError("adapter changed")

    monkeypatch.setattr("pingo.desktop.local_ipv4", failed)
    result = Api(desktop).refresh_addresses()["data"]
    assert result["interfaces"] == rows and "may be old" in result["error"]


def test_pythonw_gui_uses_console_interpreter_for_worker(desktop, monkeypatch):
    monkeypatch.setattr("pingo.desktop.sys.platform", "win32")
    monkeypatch.setattr("pingo.desktop.sys.executable", "C:/Python/pythonw.exe")
    assert Path(desktop._worker_command()[0]).name == "python.exe"


def test_worker_spawn_failure_leaves_a_recoverable_idle_window(desktop, monkeypatch):
    p = connection(desktop)
    monkeypatch.setattr("pingo.desktop.elevated", lambda: True)

    def fail(*_args, **_kwargs):
        raise FileNotFoundError("companion worker missing")

    monkeypatch.setattr("pingo.desktop.subprocess.Popen", fail)
    result = Api(desktop).start(p["id"], "listen")
    assert not result["ok"]
    assert desktop.job["state"] == "failed" and desktop.process is None
    assert desktop.job["error"]["text"] == "companion worker missing"


def test_vpn_cancel_during_authentication_cleans_protection_normally(monkeypatch):
    stop = threading.Event()
    exits = []

    class Resource:
        name = "pingo0"

        def __init__(self, *_args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, kind, *_args):
            exits.append(kind)

        def connect(self, *_args, **_kwargs):
            stop.set()
            raise InterruptedError("cancelled")

    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "Tun", Resource)
    monkeypatch.setattr("pingo.network.LinuxKillSwitch", Resource)
    monkeypatch.setattr(cli, "Routes", lambda *_: None)
    monkeypatch.setattr(cli, "VPN", lambda *_a, **_k: SimpleNamespace(reset=lambda: None))
    args = SimpleNamespace(
        address="10.77.0.1/30",
        allowed_source=[],
        no_dns=True,
        dns=[],
        kill_switch=True,
        default_route=False,
        listen=False,
        interface="pingo0",
        route=[],
        reconnects=10,
    )
    config = SimpleNamespace(peer="192.0.2.20", attempts=8, retry_seconds=0.75)
    cli.run_vpn(Resource, config, args, stop, None)
    # Endpoint sees the interruption; the outer guard/TUN see normal exit and remove protection.
    assert exits == [InterruptedError, None, None]


def test_worker_lifecycle_uses_pipes_and_waits_for_safe_stop(desktop, tmp_path, monkeypatch):
    p = connection(desktop)
    monkeypatch.setattr("pingo.desktop.elevated", lambda: True)
    script = tmp_path / "fake_worker.py"
    script.write_text(
        "import json,sys,time\n"
        "request=json.loads(sys.stdin.readline())\n"
        "print(json.dumps({'event':'state','state':'listening'}),flush=True)\n"
        "print(json.dumps({'event':'message','text':'<script>alert(1)</script>'}),flush=True)\n"
        "sys.stdin.readline()\n"
        "time.sleep(.1)\n"
        "print(json.dumps({'event':'finished','code':130}),flush=True)\n"
        "sys.exit(130)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(desktop, "_worker_command", lambda: [sys.executable, str(script)])
    desktop.start(p["id"], "listen")
    deadline = time.monotonic() + 5
    while desktop.job["state"] != "listening" and time.monotonic() < deadline:
        time.sleep(0.01)
    assert desktop.job["state"] == "listening"
    with pytest.raises(RuntimeError, match="Stop"):
        desktop.start(p["id"], "message", {"text": "second process"})
    with pytest.raises(RuntimeError, match="Stop"):
        desktop.save_profile(p)
    assert desktop.closing() is False
    assert desktop.process is not None
    desktop.monitor.join(5)
    assert desktop.process is None and desktop.job["state"] == "stopped"
    assert any(e.get("text") == "<script>alert(1)</script>" for e in desktop.events)


def test_ring_buffer_bounds_hex_records_and_reports_missed_events(desktop):
    for _ in range(2100):
        desktop._event(
            {
                "event": "traffic",
                "direction": "tx",
                "layer": "icmp",
                "wire_hex": "abcd",
                "bytes_total": 10,
                "packets_total": 1,
                "bytes_per_second": 5,
            }
        )
    snapshot = desktop.snapshot(0)
    assert len(desktop.events) == 2000
    assert snapshot["missed"] == 100 and len(snapshot["events"]) == 400
    assert all(e["wire_hex"] == "abcd" for e in snapshot["events"])


def test_worker_reports_config_error_without_touching_network(tmp_path):
    request = json.dumps({"argv": ["message", "--config", str(tmp_path / "missing.toml"), "hello"]})
    result = subprocess.run(
        [sys.executable, "-m", "pingo.desktop_worker"],
        input=request + "\n",
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout.splitlines()[-1]) == {"event": "finished", "code": 1}
    assert "No such file" in result.stderr


def test_cancel_during_handshake_is_prompt_and_does_not_retry():
    a, b = carriers()
    stop = threading.Event()
    timer = threading.Timer(0.05, stop.set)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(InterruptedError):
            Endpoint(a, KEY).connect(20, 2, stop)
        assert time.monotonic() - started < 1
        assert len(a.sent) == 1
    finally:
        timer.cancel()
        a.close()
        b.close()


def test_cancel_during_fragment_wait_is_prompt():
    a, b = carriers()
    stop = threading.Event()
    endpoint = Endpoint(a, KEY)
    endpoint.check = lambda: None
    endpoint.send = lambda _: None
    sender = Reliable(endpoint, attempts=20, timeout=2, stop=stop)
    timer = threading.Timer(0.05, stop.set)
    timer.start()
    try:
        started = time.monotonic()
        with pytest.raises(InterruptedError):
            sender.send(b"data")
        assert time.monotonic() - started < 0.5
    finally:
        timer.cancel()
        a.close()
        b.close()


def test_transfer_progress_finishes_only_after_receiver_verification(tmp_path):
    receiver = ResumableReceiver(tmp_path / "received")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"hello" * 20000)
    progress = []
    with connected(handler=receiver.handle) as (_, _, sender, _):
        name = send_resumable(sender, source, progress=lambda *args: progress.append(args))
    assert progress[0] == (0, source.stat().st_size, "connecting")
    assert progress[-2][2] == "verifying" and progress[-1][2] == "verified"
    assert progress[-1][0] == source.stat().st_size
    assert (receiver.directory / name).read_bytes() == source.read_bytes()


def test_gui_cli_events_deliver_messages_and_files_with_hex(tmp_path, monkeypatch):
    key = tmp_path / "peer.key"
    generate_key(key)
    config_path = tmp_path / "peer.toml"
    config_path.write_text('peer="192.0.2.20"\nkey_file="peer.key"\n', encoding="utf-8")
    config = Config.load(config_path)
    a, b = carriers()
    events = []
    stop = threading.Event()
    server = Endpoint(b, config.key(), persistent=True)
    listener_args = SimpleNamespace(resume_retention=86400, reconnects=0)
    thread = threading.Thread(
        target=cli.run_listener,
        args=(
            lambda: server,
            config,
            listener_args,
            stop,
            lambda kind, **fields: events.append({"event": kind, **fields}),
        ),
    )
    thread.start()
    deadline = time.monotonic() + 2
    while not any(e.get("state") == "listening" for e in events) and time.monotonic() < deadline:
        time.sleep(0.01)
    # One process per endpoint at a time, with a fresh carrier for each sender session.
    monkeypatch.setattr(cli, "RawICMP", lambda *_: a)
    sender_events = []

    def emit(kind, **fields):
        sender_events.append({"event": kind, **fields})

    try:
        assert cli.main(["message", "--config", str(config_path), "hello"], events=emit) == 0
        assert any(e.get("text") == "hello" for e in events)
        a.closed = False
        source = tmp_path / "file.txt"
        source.write_text("desktop transfer" * 3000, encoding="utf-8")
        assert cli.main(["file", "--config", str(config_path), str(source)], events=emit) == 0
        received = next(e for e in events if e["event"] == "received_file")
        assert (config.receive_dir / received["name"]).read_bytes() == source.read_bytes()
        assert any(e["event"] == "sent_file" for e in sender_events)
    finally:
        stop.set()
        thread.join(3)
        server.close()


def test_inline_desktop_assets_require_no_remote_resources():
    html = page_html()
    assert "<script src=" not in html and '<link rel="stylesheet"' not in html
    assert "connect-src 'none'" in html
    assert 'id="show-hex" type="checkbox" checked' in html
