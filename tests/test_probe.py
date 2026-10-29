import threading

import pytest

from pingo import cli
from pingo.config import generate_key
from pingo.transport import Endpoint

from .helpers import carriers


@pytest.mark.parametrize("failure", [None, "key", "mode", "cancel"])
def test_probe_verifies_real_handshake_without_application_data(tmp_path, monkeypatch, failure):
    key_path = tmp_path / "peer.key"
    generate_key(key_path)
    config = tmp_path / "peer.toml"
    config.write_text('peer="192.0.2.20"\nkey_file="peer.key"\nattempts=3\nretry_seconds=0.05\n')
    a, b = carriers()
    monkeypatch.setattr(cli, "RawICMP", lambda *_: a)
    events, received = [], []
    key = b"x" * 32 if failure == "key" else key_path.read_bytes()
    stop = threading.Event()
    if failure == "cancel":
        stop.set()
    with Endpoint(b, key, "vpn" if failure == "mode" else "direct") as server:
        server.handler = received.append
        server.start(responder=True)
        code = cli.main(
            ["probe", "--config", str(config), "--traffic", "off"],
            events=lambda event, **fields: events.append({"event": event, **fields}),
            stop=stop,
        )
        assert code == (130 if failure == "cancel" else 1 if failure else 0)
        assert any(e["event"] == "peer_verified" for e in events) is (failure is None)
        assert received == []
        assert a.closed
