"""Opt-in real ICMP/TUN/firewall tests inside disposable Linux network namespaces."""

import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        sys.platform != "linux" or os.environ.get("PINGO_LIVE") != "1",
        reason="requires explicit PINGO_LIVE=1 on isolated Linux with NET_ADMIN/SYS_ADMIN",
    ),
]


def run(args, check=True, timeout=15):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=timeout)


def wait_for(predicate, processes=(), timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise AssertionError(
                    f"peer exited with code {process.returncode}: {process.err_path.read_text()}"
                )
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError("live condition was not reached before timeout")


class Lab:
    def __init__(self, root):
        self.root = root
        token = uuid.uuid4().hex[:8]
        self.a, self.b = f"pingo_a_{token}", f"pingo_b_{token}"
        self.processes, self.streams = [], []
        self.namespaces = []
        key = root / "peer.key"
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        for name, peer, bind in (
            ("a", "169.254.210.2", "169.254.210.1"),
            ("b", "169.254.210.1", "169.254.210.2"),
        ):
            (root / f"{name}.toml").write_text(
                f'peer="{peer}"\nbind="{bind}"\nkey_file="peer.key"\n'
                f'receive_dir="received-{name}"\nretry_seconds=0.05\nattempts=4\n'
            )

    def setup(self):
        for namespace in (self.a, self.b):
            run(["ip", "netns", "add", namespace])
            self.namespaces.append(namespace)
        first, second = "pa" + uuid.uuid4().hex[:8], "pb" + uuid.uuid4().hex[:8]
        run(["ip", "link", "add", first, "type", "veth", "peer", "name", second])
        run(["ip", "link", "set", first, "netns", self.a])
        run(["ip", "link", "set", second, "netns", self.b])
        for namespace, interface, address in (
            (self.a, first, "169.254.210.1/29"),
            (self.b, second, "169.254.210.2/29"),
        ):
            run(["ip", "-n", namespace, "address", "add", address, "dev", interface])
            run(["ip", "-n", namespace, "link", "set", interface, "up"])
            run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        self.outer_a, self.outer_b = first, second
        # This address is directly reachable outside the tunnel for leak tests.
        run(["ip", "-n", self.b, "address", "add", "169.254.210.3/32", "dev", second])

    def exec(self, side, args, **kwargs):
        return run(["ip", "netns", "exec", getattr(self, side), *args], **kwargs)

    def cli(self, side, command, *extra):
        return [
            "ip",
            "netns",
            "exec",
            getattr(self, side),
            sys.executable,
            "-m",
            "pingo",
            command,
            "--config",
            str(self.root / f"{side}.toml"),
            *extra,
        ]

    def start(self, side, command, *extra):
        number = len(self.processes)
        out_path, err_path = self.root / f"{number}.out", self.root / f"{number}.err"
        out, err = out_path.open("w"), err_path.open("w")
        self.streams.extend([out, err])
        process = subprocess.Popen(self.cli(side, command, *extra), stdout=out, stderr=err)
        process.err_path, process.out_path = err_path, out_path
        self.processes.append(process)
        return process

    def stop(self, process, hard=False):
        if process.poll() is None:
            process.kill() if hard else process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def close(self):
        for process in reversed(self.processes):
            self.stop(process)
        for stream in self.streams:
            stream.close()
        for namespace in reversed(self.namespaces):
            run(["ip", "netns", "del", namespace], check=False)


@pytest.fixture
def lab(tmp_path):
    for executable in ("ip", "ping", "nft"):
        if not shutil.which(executable):
            pytest.fail(f"live test dependency missing: {executable}")
    if not Path("/dev/net/tun").exists():
        pytest.fail("live test dependency missing: /dev/net/tun")
    result = Lab(tmp_path)
    try:
        result.setup()
        yield result
    finally:
        result.close()


def test_live_raw_icmp_message_file_and_immediate_traffic(lab):
    listener = lab.start("b", "listen")
    wait_for(lambda: "Listening" in listener.err_path.read_text(), [listener])
    message = run(lab.cli("a", "message", "live ICMP hello", "--reconnects", "0"))
    assert "message received" in message.stdout
    wait_for(lambda: "live ICMP hello" in listener.out_path.read_text(), [listener])
    data = os.urandom(80000)
    source = lab.root / "source.bin"
    source.write_bytes(data)
    transfer = run(lab.cli("a", "file", str(source), "--traffic", "off"), timeout=30)
    filename = transfer.stdout.strip().split(": ", 1)[1]
    assert (lab.root / "received-b" / filename).read_bytes() == data
    events = [
        json.loads(line)
        for line in listener.err_path.read_text().splitlines()
        if line.startswith('{"event":"traffic"')
    ]
    assert any(event["direction"] == "tx" for event in events)
    assert any(event["direction"] == "rx" and event.get("wire_hex") for event in events)


def test_live_file_resumes_after_receiver_process_restart(lab):
    listener = lab.start("b", "listen", "--traffic", "off")
    wait_for(lambda: "Listening" in listener.err_path.read_text(), [listener])
    source = lab.root / "large.bin"
    data = os.urandom(1024 * 1024)
    source.write_bytes(data)
    sender = lab.start("a", "file", str(source), "--traffic", "off")
    directory = lab.root / "received-b"

    def checkpoint():
        for path in directory.glob("*.resume.json"):
            try:
                record = json.loads(path.read_text())
                if 0 < record["offset"] < record["size"]:
                    return record["offset"]
            except (FileNotFoundError, json.JSONDecodeError):
                continue

    offset = wait_for(checkpoint, [sender, listener])
    lab.stop(listener, hard=True)
    replacement = lab.start("b", "listen", "--traffic", "off")
    wait_for(lambda: "Listening" in replacement.err_path.read_text(), [replacement])
    assert sender.wait(timeout=60) == 0, sender.err_path.read_text()
    filename = sender.out_path.read_text().strip().split(": ", 1)[1]
    assert offset > 0 and (directory / filename).read_bytes() == data
    assert len(list(directory.glob("*-large.bin"))) == 1


def vpn_pair(lab):
    server = lab.start("b", "vpn", "--listen", "--address", "10.77.0.2/30", "--traffic", "summary")
    wait_for(lambda: "Waiting" in server.err_path.read_text(), [server])
    client = lab.start(
        "a",
        "vpn",
        "--address",
        "10.77.0.1/30",
        "--default-route",
        "--no-dns",
        "--traffic",
        "summary",
    )
    wait_for(lambda: "VPN ready" in client.err_path.read_text(), [client, server])
    wait_for(lambda: "VPN ready" in server.err_path.read_text(), [client, server])
    return client, server


def test_live_tun_ping_routing_and_normal_cleanup(lab):
    baseline = lab.exec("a", ["ip", "-j", "-4", "route", "show"]).stdout
    client, server = vpn_pair(lab)
    result = lab.exec("a", ["ping", "-c", "3", "-W", "2", "10.77.0.2"])
    assert "0% packet loss" in result.stdout
    leaked = lab.exec("a", ["ping", "-c", "1", "-W", "1", "169.254.210.3"], check=False)
    assert leaked.returncode != 0
    assert '"layer":"tun"' in server.err_path.read_text()
    lab.stop(client)
    assert lab.exec("a", ["ip", "-j", "-4", "route", "show"]).stdout == baseline
    assert "pingo_" not in lab.exec("a", ["nft", "list", "tables"]).stdout
    assert lab.exec("a", ["ip", "link", "show", "pingo0"], check=False).returncode != 0


def test_live_kill_switch_survives_crash_and_explicit_unlock(lab):
    client, _ = vpn_pair(lab)
    table = re.search(r"pingo_[0-9a-f]{32}", client.err_path.read_text()).group()
    lab.stop(client, hard=True)
    assert table in lab.exec("a", ["nft", "list", "tables"]).stdout
    leaked = lab.exec("a", ["ping", "-c", "1", "-W", "1", "169.254.210.3"], check=False)
    assert leaked.returncode != 0
    lab.exec("a", [sys.executable, "-m", "pingo", "unlock", "--table", table])
    assert table not in lab.exec("a", ["nft", "list", "tables"]).stdout
    assert lab.exec("a", ["ping", "-c", "1", "-W", "2", "169.254.210.3"]).returncode == 0


def test_live_vpn_reconnects_after_responder_restart(lab):
    client, server = vpn_pair(lab)
    lab.exec("a", ["ping", "-c", "1", "-W", "2", "10.77.0.2"])
    lab.stop(server)
    replacement = lab.start("b", "vpn", "--listen", "--address", "10.77.0.2/30", "--traffic", "off")
    wait_for(lambda: "Waiting" in replacement.err_path.read_text(), [replacement])
    wait_for(lambda: "reconnecting" in client.err_path.read_text(), [client], timeout=45)
    wait_for(
        lambda: "VPN ready" in replacement.err_path.read_text(), [client, replacement], timeout=30
    )
    lab.exec("a", ["ping", "-c", "2", "-W", "3", "10.77.0.2"])
