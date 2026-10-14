import os

import pytest

from pingo.cli import main
from pingo.config import Config, generate_key


def test_keygen_private_no_overwrite(tmp_path):
    path = tmp_path / "keys" / "peer.key"
    generate_key(path)
    assert len(path.read_bytes()) == 32
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        generate_key(path)
    assert path.read_bytes() == original
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_keygen_permission_failure_removes_unwritten_key(tmp_path, monkeypatch):
    path = tmp_path / "peer.key"

    def fail(_path):
        assert _path.read_bytes() == b""
        raise PermissionError("cannot secure key")

    monkeypatch.setattr("pingo.config.private_file", fail)
    with pytest.raises(PermissionError, match="secure"):
        generate_key(path)
    assert not path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFOs")
def test_key_fifo_is_rejected_without_waiting_for_a_writer(tmp_path):
    path = tmp_path / "key-fifo"
    os.mkfifo(path, 0o600)
    with pytest.raises(ValueError, match="regular file"):
        Config("192.0.2.20", path).key()


def test_paths_are_relative_to_config(tmp_path):
    key = tmp_path / "keys" / "peer.key"
    generate_key(key)
    path = tmp_path / "local.toml"
    path.write_text('peer = "192.0.2.20"\nkey_file = "keys/peer.key"\n', encoding="utf-8")
    config = Config.load(path)
    assert config.key_file == key
    assert config.receive_dir == tmp_path / "received"
    assert config.key() == key.read_bytes()


@pytest.mark.parametrize(
    "extra",
    [
        "attempts = 21",
        "retry_seconds = 0.001",
        "max_file_bytes = -1",
        "max_receive_bytes = -1",
        'unknown = "x"',
        'bind = "::1"',
    ],
)
def test_bad_config(tmp_path, extra):
    path = tmp_path / "local.toml"
    path.write_text('peer = "192.0.2.20"\nkey_file = "peer.key"\n' + extra, encoding="utf-8")
    with pytest.raises(ValueError):
        Config.load(path)


def test_invalid_key(tmp_path):
    key = tmp_path / "peer.key"
    key.write_bytes(b"bad")
    key.chmod(0o600)
    with pytest.raises(ValueError, match="32"):
        Config("192.0.2.20", key).key()


@pytest.mark.parametrize(
    "body",
    [
        "",
        'peer = "192.0.2.20"',
        'peer = 1\nkey_file = "x"',
        'peer = "0.0.0.0"\nkey_file = "x"',
        'peer = "239.1.2.3"\nkey_file = "x"',
        'peer = "192.0.2.20"\nkey_file = 1',
    ],
)
def test_required_fields_and_types(tmp_path, body):
    path = tmp_path / "local.toml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        Config.load(path)


def test_cli_keygen_and_help(tmp_path, capsys):
    assert main(["keygen", str(tmp_path / "peer.key")]) == 0
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "vpn" in capsys.readouterr().out


def test_windows_vpn_requires_explicit_driver_before_socket(tmp_path, monkeypatch, caplog):
    generate_key(tmp_path / "peer.key")
    config = tmp_path / "local.toml"
    config.write_text('peer = "192.0.2.20"\nkey_file = "peer.key"\n', encoding="utf-8")
    monkeypatch.setattr("pingo.cli.sys.platform", "win32")
    assert main(["vpn", "--config", str(config), "--address", "10.77.0.1/30"]) == 1
    assert "Windows VPN requires --wintun-dll" in caplog.text


@pytest.mark.parametrize(
    "resolver", ["0.0.0.0", "224.0.0.1", "127.0.0.1", "255.255.255.255", "192.0.2.20"]
)
def test_invalid_dns_rejected_before_any_network_changes(tmp_path, monkeypatch, caplog, resolver):
    generate_key(tmp_path / "peer.key")
    config = tmp_path / "local.toml"
    config.write_text('peer="192.0.2.20"\nkey_file="peer.key"\n', encoding="utf-8")

    def fail_if_opened(*_):
        pytest.fail("must reject invalid DNS before opening the adapter")

    monkeypatch.setattr("pingo.cli.Tun", fail_if_opened)
    assert (
        main(["vpn", "--config", str(config), "--address", "10.77.0.1/30", "--dns", resolver]) == 1
    )
    assert "DNS must be a unicast IPv4 resolver" in caplog.text
