"""Local HTML desktop shell with a small native bridge and isolated CLI worker."""

import argparse
import ctypes
import functools
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from . import __version__
from .config import Config, generate_key
from .diagnostics import address_checks, local_network_checks, storage_checks, vpn_checks
from .permissions import desktop_owner, private_directory, private_file

PROFILE_FIELDS = {
    "name",
    "peer",
    "bind",
    "key_file",
    "receive_dir",
    "retry_seconds",
    "attempts",
    "max_file_bytes",
    "max_receive_bytes",
    "reconnects",
    "resume_retention",
    "wintun_dll",
    "address",
    "interface",
    "routes",
    "allowed_source",
    "dns",
    "no_dns",
    "default_route",
    "kill_switch",
    "vpn_listen",
}
CONFIG_FIELDS = {
    "peer",
    "bind",
    "key_file",
    "receive_dir",
    "retry_seconds",
    "attempts",
    "max_file_bytes",
    "max_receive_bytes",
}


def data_directory():
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Pingo"
    if sys.platform == "darwin":
        owner = desktop_owner()
        home = Path.home()
        if owner is not None:
            import pwd

            home = Path(pwd.getpwuid(owner[0]).pw_dir)
        return home / "Library/Application Support/Pingo"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "pingo"


def elevated():
    if sys.platform == "win32":
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return hasattr(os, "geteuid") and os.geteuid() == 0


def atomic_write(path, text):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            private_file(temporary)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def config_text(profile):
    return "".join(f"{key} = {json.dumps(profile[key])}\n" for key in sorted(CONFIG_FIELDS))


def error_hint(text):
    value = text.lower()
    if "setup check failed" in value:
        return "Open Settings for the full check results, correct the connection, then try again."
    if any(item in value for item in (
        "10049", "cannot assign requested address", "not valid in its context",
    )):
        return (
            "This computer's saved IPv4 may have changed. Select an address assigned to an active "
            "adapter, or use 0.0.0.0, then update the other computer's peer address too."
        )
    if any(item in value for item in ("network is unreachable", "no route", "10051", "10065")):
        return "Check the active adapter, peer IPv4 and routes. Another VPN may change the route."
    if any(item in value for item in ("10013", "permission", "access is denied", "administrator")):
        return "Windows: reopen as Administrator. macOS/Linux: launch Pingo with sudo/root."
    if any(item in value for item in ("authenticate", "confirm session", "not acknowledged")):
        return (
            "Ask the other person to start Receive (or the VPN responder). Check both IPv4 "
            "addresses, the same shared key, and inbound ICMP echo requests in both firewalls. "
            "Both computers need Pingo 0.3 or later. "
            "NAT, guest Wi-Fi isolation, another VPN, or ICMP filtering/rate limits can block it. "
            "A successful ping alone does not verify this; use Settings → Test peer connection. "
            "Check the receiver before resending a message."
        )
    if "key" in value:
        return "Choose a Pingo 32-byte key file. Both computers must use the same key."
    if "wintun" in value:
        return "Choose the signed official wintun.dll matching this app in VPN settings."
    if "quota" in value or "limit" in value:
        return "Check the configured file limits and free space; move old received files if needed."
    if "no such file" in value or "cannot find" in value:
        return "Choose the file again and check that it still exists at the saved location."
    return "Check your connection settings and the activity log for details."


def bridge_action(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return {"ok": True, "data": function(*args, **kwargs)}
        except (
            OSError,
            ValueError,
            RuntimeError,
            KeyError,
            TypeError,
            subprocess.SubprocessError,
        ) as exc:
            return {"ok": False, "error": str(exc), "hint": error_hint(str(exc))}

    return wrapped


class Desktop:
    """Not exposed to JavaScript; the Api below defines the complete bridge."""

    def __init__(self, root=None):
        self.root = Path(root or data_directory()).resolve()
        private_directory(self.root)
        # Repair explicit grants on app-owned files created by earlier versions.
        owned = [self.root / "connections.json"]
        key_directory = self.root / "keys"
        if key_directory.exists():
            private_directory(key_directory)
            owned.extend(
                path
                for path in key_directory.glob("*.key")
                if re.fullmatch(r"[0-9a-f]{32}\.key", path.name)
            )
        owned.extend(
            path
            for path in self.root.glob("*.toml")
            if re.fullmatch(r"(?:job-)?[0-9a-f]{32}\.toml", path.name)
        )
        for path in owned:
            if path.is_symlink():
                raise ValueError("private storage files must not be symbolic links")
            if path.is_file():
                private_file(path)
        self.profiles = {}
        self.selected = None
        self.window = None
        self.process = None
        self.job = {"state": "idle", "action": None, "error": None}
        self.events = deque(maxlen=2000)
        self.sequence = 0
        self.lock = threading.RLock()
        self.close_pending = False
        self.metrics = {}
        self.recovery_table = ""
        self.monitor = None
        try:
            self.local_addresses = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
                    if not ipaddress.IPv4Address(item[4][0]).is_loopback
                }
            )
        except OSError:
            self.local_addresses = []
        self._load()

    def _load(self):
        path = self.root / "connections.json"
        if path.exists():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                self.profiles = value["profiles"]
                self.selected = value.get("selected")
                if not isinstance(self.profiles, dict):
                    raise ValueError("invalid saved connections")
                for identifier, profile in self.profiles.items():
                    self._config_path(identifier)
                    if not isinstance(profile, dict) or profile.get("id") != identifier:
                        raise ValueError("invalid saved connection")
                    if set(profile) != PROFILE_FIELDS | {"id"}:
                        raise ValueError("incomplete saved connection; import its TOML settings")
                    self._config(profile)
                if self.selected not in self.profiles:
                    self.selected = next(iter(self.profiles), None)
            except (ValueError, KeyError, TypeError) as exc:
                self.profiles = {}
                self.selected = None
                self._event({"event": "log", "level": "error", "text": str(exc)})

    def _save(self, profiles=None, selected=None):
        atomic_write(
            self.root / "connections.json",
            json.dumps(
                {
                    "profiles": self.profiles if profiles is None else profiles,
                    "selected": self.selected if selected is None else selected,
                },
                indent=2,
            ),
        )

    def _config(self, profile):
        return Config.from_data({key: profile[key] for key in CONFIG_FIELDS}, self.root)

    def _idle(self):
        if self.process is not None:
            raise RuntimeError("Stop the current activity before changing the connection.")

    def _profile(self, identifier):
        if identifier not in self.profiles:
            raise ValueError("Choose or create a connection first.")
        return self.profiles[identifier]

    def _config_path(self, identifier):
        # Never accept a filesystem path as an identifier.
        if not re.fullmatch(r"[0-9a-f]{32}", identifier):
            raise ValueError("invalid connection identity")
        return self.root / (identifier + ".toml")

    def _event(self, event):
        with self.lock:
            self.sequence += 1
            event = {**event, "seq": self.sequence, "at": time.time()}
            self.events.append(event)
            kind = event.get("event")
            if kind == "state":
                self.job["state"] = event["state"]
            elif kind == "progress":
                self.job["progress"] = event
            elif kind == "traffic":
                self.metrics[event["layer"] + ":" + event["direction"]] = {
                    key: event[key] for key in ("bytes_total", "packets_total", "bytes_per_second")
                }
            elif kind in ("error", "log"):
                text = event.get("text", "")
                if event.get("level") == "error" or kind == "error":
                    self.job["error"] = {"text": text, "hint": error_hint(text)}
                match = re.search(r"pingo_[0-9a-f]{32}", text)
                if match:
                    self.recovery_table = match.group()

    def snapshot(self, after=0):
        after = max(0, int(after))
        with self.lock:
            first = self.events[0]["seq"] if self.events else self.sequence + 1
            return {
                "version": __version__,
                "platform": sys.platform,
                "elevated": elevated(),
                "profiles": list(self.profiles.values()),
                "selected": self.selected,
                "job": {**self.job, "running": self.process is not None},
                "events": [item for item in self.events if item["seq"] > after][:400],
                "missed": max(0, first - after - 1),
                "metrics": dict(self.metrics),
                "recovery_table": self.recovery_table,
                "local_addresses": self.local_addresses,
            }

    def save_profile(self, data):
        with self.lock:
            self._idle()
            if not isinstance(data, dict) or set(data) - PROFILE_FIELDS - {"id"}:
                raise ValueError("invalid connection settings")
            identifier = data.get("id") or uuid.uuid4().hex
            target = self._config_path(identifier)
            defaults = {
                "name": "My connection",
                "bind": "0.0.0.0",
                "receive_dir": str(self.root / "received"),
                "retry_seconds": 0.75,
                "attempts": 8,
                "max_file_bytes": 64 * 1024**2,
                "max_receive_bytes": 256 * 1024**2,
                "reconnects": 10,
                "resume_retention": 86400,
                "wintun_dll": "",
                "address": "10.77.0.1/30",
                "interface": "pingo0",
                "routes": [],
                "allowed_source": [],
                "dns": [],
                "no_dns": False,
                "default_route": False,
                "kill_switch": None,
                "vpn_listen": False,
            }
            profile = {**defaults, **data, "id": identifier}
            if not isinstance(profile["name"], str) or not profile["name"].strip():
                raise ValueError("Give this connection a name.")
            profile["name"] = profile["name"].strip()[:80]
            for field in ("key_file", "receive_dir"):
                if not isinstance(profile.get(field), str) or not profile[field].strip():
                    raise ValueError(f"Choose a {field.replace('_', ' ')}.")
                profile[field] = str(Path(profile[field]).expanduser().resolve())
            for field, low, high in (("reconnects", 0, 20), ("resume_retention", 60, 604800)):
                if type(profile[field]) is not int or not low <= profile[field] <= high:
                    raise ValueError(f"{field} must be {low}..{high}")
            ipaddress.IPv4Interface(profile["address"])
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", profile["interface"]):
                raise ValueError("Interface name must contain 1..15 letters, numbers, '_' or '-'.")
            for field in ("routes", "allowed_source", "dns"):
                if not isinstance(profile[field], list) or len(profile[field]) > 32:
                    raise ValueError(f"{field} must be a list of at most 32 addresses")
                for item in profile[field]:
                    (ipaddress.IPv4Address if field == "dns" else ipaddress.IPv4Network)(item)
            for field in ("no_dns", "default_route", "vpn_listen"):
                if type(profile[field]) is not bool:
                    raise ValueError(f"invalid {field}")
            if profile["kill_switch"] is not None and type(profile["kill_switch"]) is not bool:
                raise ValueError("invalid kill switch setting")
            if not isinstance(profile["wintun_dll"], str):
                raise ValueError("invalid driver path")
            # Validate a temporary config without altering a working saved connection on failure.
            temporary = self.root / (uuid.uuid4().hex + ".toml")
            try:
                atomic_write(temporary, config_text(profile))
                config = Config.load(temporary)
                config.key()
                atomic_write(target, config_text(profile))
            finally:
                temporary.unlink(missing_ok=True)
            profiles = {**self.profiles, identifier: profile}
            self._save(profiles, identifier)
            self.profiles = profiles
            self.selected = identifier
            return profile

    def check(self, identifier):
        self._idle()
        profile = self._profile(identifier)
        results = []

        def item(name, status, detail):
            results.append({"name": name, "status": status, "detail": detail})

        try:
            config = self._config(profile)
            config.key()
            item(
                "Connection and shared key", "pass",
                "Settings are valid; key contains 32 bytes. The peer's key is unverified locally.",
            )
            results.extend(address_checks(config.peer, config.bind))
            results.extend(local_network_checks(config.peer, config.bind))
            results.extend(storage_checks(config))
        except (OSError, ValueError) as exc:
            item("Connection and shared key", "fail", str(exc))
        item(
            "Network permissions",
            "pass" if elevated() else "fail",
            "Running as Administrator/root; the ICMP socket check verifies actual carrier access."
            if elevated()
            else "Windows: reopen as Administrator. macOS/Linux: launch with sudo/root.",
        )
        item(
            "Supported operating system",
            "pass" if sys.platform in ("win32", "linux", "darwin") else "fail",
            "Windows, macOS and Linux are supported.",
        )
        item(
            "Peer and firewall",
            "manual",
            f"Other computer: {profile['peer']}. It must be receiving in the same mode and use "
            "the same key. Allow ICMP echo requests (type 8) from each peer. This check does "
            "not contact the peer or prove that the network path works. Both peers send requests; "
            "allowing only echo replies is insufficient. Scope firewall rules to the peer IPv4 "
            "and the active network profile; do not turn the firewall off.",
        )
        results.extend(vpn_checks(profile))
        if sys.platform == "win32":
            exists = bool(profile["wintun_dll"]) and Path(profile["wintun_dll"]).is_file()
            item(
                "VPN driver (VPN only)",
                "pass" if exists else "manual",
                "DLL found; signature is checked before use."
                if exists
                else "Choose the official signed wintun.dll in VPN settings. "
                "Messages/files do not need it.",
            )
        elif sys.platform == "darwin":
            item(
                "macOS capture and VPN",
                "manual",
                "Uses system libpcap and a fresh utun adapter. Root is required for networking. "
                "The kill switch requires the standard com.apple/* PF hook and resets existing "
                "PF connections. DNS changes are restored on stop or with pingo unlock.",
            )
        elif sys.platform == "linux":
            ready = Path("/dev/net/tun").exists() and bool(shutil.which("ip"))
            item(
                "TUN and iproute2 (VPN only)",
                "pass" if ready else "manual",
                "TUN and ip found." if ready else "VPN requires /dev/net/tun and iproute2.",
            )
            item(
                "Kill switch and DNS (VPN only)",
                "manual",
                "Kill switch requires nft; automatic DNS requires resolvectl/systemd-resolved. "
                f"Found: nft={bool(shutil.which('nft'))}, "
                f"resolvectl={bool(shutil.which('resolvectl'))}.",
            )
        return results

    def start(self, identifier, action, payload=None):
        payload = payload or {}
        with self.lock:
            self._idle()
            if action not in ("listen", "message", "file", "vpn", "unlock", "probe"):
                raise ValueError("unsupported action")
            if not elevated():
                raise PermissionError("Network actions require Administrator/root permissions.")
            job_config = None
            if action == "unlock":
                argv = ["unlock"]
                if sys.platform == "linux":
                    table = payload.get("table", "")
                    if not re.fullmatch(r"pingo_[0-9a-f]{32}", table):
                        raise ValueError("Enter the exact pingo_<32 hex digits> recovery table.")
                    argv += ["--table", table]
            else:
                profile = self._profile(identifier)
                config = self._config(profile)
                config.key()
                checks = address_checks(config.peer, config.bind)
                if action == "vpn":
                    checks.extend(vpn_checks(profile))
                failures = [c["detail"] for c in checks if c["status"] == "fail"]
                if failures:
                    raise ValueError("Setup check failed: " + " ".join(failures))
                job_config = self.root / ("job-" + uuid.uuid4().hex + ".toml")
                argv = [
                    action,
                    "--config",
                    str(job_config),
                    "--traffic",
                    "hex",
                    "--reconnects",
                    str(profile["reconnects"]),
                ]
                if action == "message":
                    text = payload.get("text")
                    if not isinstance(text, str) or not text or len(text.encode()) > 60000:
                        raise ValueError("Enter a message of 1..60000 UTF-8 bytes.")
                    argv += ["--", text]
                elif action == "file":
                    path = Path(payload.get("path", ""))
                    if not path.is_file() or path.stat().st_size > config.max_file_bytes:
                        raise ValueError(
                            "Choose an existing file within the configured size limit."
                        )
                    argv += ["--", str(path.resolve())]
                elif action == "listen":
                    argv += ["--resume-retention", str(profile["resume_retention"])]
                elif action == "vpn":
                    argv += ["--address", profile["address"], "--interface", profile["interface"]]
                    if profile["vpn_listen"]:
                        if profile["default_route"] or profile["kill_switch"]:
                            raise ValueError(
                                "VPN responders must not enable default route or kill switch."
                            )
                        argv += ["--listen"]
                    if sys.platform == "win32":
                        if not profile["wintun_dll"]:
                            raise ValueError(
                                "Choose the official wintun.dll in VPN settings first."
                            )
                        argv += ["--wintun-dll", profile["wintun_dll"]]
                    for field, flag in (
                        ("routes", "--route"),
                        ("allowed_source", "--allowed-source"),
                        ("dns", "--dns"),
                    ):
                        for value in profile[field]:
                            argv += [flag, value]
                    if profile["no_dns"]:
                        argv += ["--no-dns"]
                    if profile["default_route"]:
                        argv += ["--default-route"]
                    if profile["kill_switch"] is not None:
                        argv += ["--kill-switch" if profile["kill_switch"] else "--no-kill-switch"]
            command = self._worker_command()
            self.job = {"state": "starting", "action": action, "error": None, "progress": None}
            self.metrics = {}
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            try:
                if job_config:
                    atomic_write(job_config, config_text(profile))
                self.process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=flags,
                    env={**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"},
                )
            except OSError as exc:
                if job_config:
                    job_config.unlink(missing_ok=True)
                self.job["state"] = "failed"
                self.job["error"] = {"text": str(exc), "hint": error_hint(str(exc))}
                raise
            self._event({"event": "state", "state": "starting", "action": action})
            self.monitor = threading.Thread(
                target=self._watch, args=(self.process, job_config), daemon=True
            )
            self.monitor.start()
            self.process.stdin.write(json.dumps({"argv": argv}) + "\n")
            self.process.stdin.flush()
            return {"started": action}

    def _worker_command(self):
        if getattr(sys, "frozen", False):
            return [
                str(
                    Path(sys.executable).with_name(
                        "Pingo-worker.exe" if sys.platform == "win32" else "Pingo-worker"
                    )
                )
            ]
        interpreter = Path(sys.executable)
        if sys.platform == "win32" and interpreter.name.lower() == "pythonw.exe":
            interpreter = interpreter.with_name("python.exe")
        return [str(interpreter), "-m", "pingo.desktop_worker"]

    def _read(self, stream):
        for line in stream:
            try:
                event = json.loads(line)
                if not isinstance(event, dict) or "event" not in event:
                    raise ValueError("not an event")
            except ValueError:
                text = line.rstrip()
                event = {
                    "event": "log",
                    "level": "error"
                    if text.startswith("ERROR:")
                    else "warning"
                    if text.startswith("WARNING:")
                    else "info",
                    "text": text,
                }
            self._event(event)
        stream.close()

    def _watch(self, process, job_config=None):
        readers = [
            threading.Thread(target=self._read, args=(stream,), daemon=True)
            for stream in (process.stdout, process.stderr)
        ]
        for reader in readers:
            reader.start()
        code = process.wait()
        for reader in readers:
            reader.join()
        with self.lock:
            if job_config:
                job_config.unlink(missing_ok=True)
            process.stdin.close()
            self.process = None
            self.job["state"] = "completed" if code == 0 else "stopped" if code == 130 else "failed"
            if code not in (0, 130) and not self.job["error"]:
                self.job["error"] = {
                    "text": f"Activity exited with code {code}.",
                    "hint": "Read the activity log and run the setup check.",
                }
            self._event({"event": "state", "state": self.job["state"], "code": code})
        if self.close_pending and self.window:
            self.window.destroy()

    def stop(self):
        with self.lock:
            if self.process:
                self.job["state"] = "stopping"
                try:
                    self.process.stdin.write("stop\n")
                    self.process.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
            return {"stopping": self.process is not None}

    def closing(self):
        with self.lock:
            if self.process:
                self.close_pending = True
                self.stop()
                return False  # Keep the window/process alive until network cleanup finishes.
        return True


class Api:
    def __init__(self, desktop):
        self._desktop = desktop

    @bridge_action
    def snapshot(self, after=0):
        return self._desktop.snapshot(after)

    @bridge_action
    def save_connection(self, data):
        return self._desktop.save_profile(data)

    @bridge_action
    def select_connection(self, identifier):
        with self._desktop.lock:
            self._desktop._idle()
            self._desktop._profile(identifier)
            self._desktop.selected = identifier
            self._desktop._save()
        return identifier

    @bridge_action
    def choose(self, kind):
        import webview

        types = {
            "key": ("Pingo keys (*.key)", "All files (*.*)"),
            "config": ("Pingo configuration (*.toml)",),
            "driver": ("Wintun driver (*.dll)",),
            "file": ("All files (*.*)",),
        }
        if kind not in {*types, "folder"}:
            raise ValueError("unsupported file picker")
        result = self._desktop.window.create_file_dialog(
            webview.FileDialog.FOLDER if kind == "folder" else webview.FileDialog.OPEN,
            file_types=types.get(kind, ()),
        )
        return str(result[0]) if result else None

    @bridge_action
    def create_key(self):
        self._desktop._idle()
        folder = self._desktop.root / "keys"
        folder.mkdir(mode=0o700, exist_ok=True)
        path = folder / (uuid.uuid4().hex + ".key")
        generate_key(path)
        return str(path)

    @bridge_action
    def import_connection(self, path):
        config = Config.load(Path(path))
        data = {
            field: str(getattr(config, field))
            if field in ("key_file", "receive_dir")
            else getattr(config, field)
            for field in CONFIG_FIELDS
        }
        data["name"] = Path(path).stem
        return self._desktop.save_profile(data)

    @bridge_action
    def export_pairing(self, identifier):
        import webview

        self._desktop._idle()
        profile = self._desktop._profile(identifier)
        if profile["bind"] == "0.0.0.0":
            raise ValueError(
                "Set 'This computer's IPv4' before creating the other computer's setup."
            )
        result = self._desktop.window.create_file_dialog(webview.FileDialog.FOLDER)
        if not result:
            return None
        folder = Path(result[0]) / ("Pingo-pair-" + uuid.uuid4().hex[:8])
        private_directory(folder)
        key = self._desktop._config(profile).key()
        with (folder / "peer.key").open("xb") as stream:
            private_file(folder / "peer.key")
            stream.write(key)
        other = {
            **profile,
            "peer": profile["bind"],
            "bind": profile["peer"],
            "key_file": "peer.key",
            "receive_dir": "received",
        }
        atomic_write(folder / "peer.toml", config_text(other))
        atomic_write(
            folder / "READ-ME.txt",
            (
                "This folder contains a SECRET shared key. "
                "Transfer it using a separate trusted channel.\n"
                "On the other computer, open Pingo and choose Import, "
                "then peer.toml.\n"
                "Allow inbound ICMP echo requests from the other endpoint on BOTH computers.\n"
                "Start Receive on one computer, then send from the other.\n"
                "Run Settings' setup check on both computers. Test peer connection verifies "
                "a direct-mode handshake while the other computer is Receiving.\n"
                "Private IPv4 addresses need a shared LAN or routed private network. Pingo "
                "has no NAT traversal; a router's public IPv4 is not your computer's address.\n"
                "Use matching Pingo versions and one instance per endpoint/key.\n"
                "Keep the key private; do not upload it to public repositories "
                "or paste it into chat.\n"
            ),
        )
        return str(folder)

    @bridge_action
    def check_setup(self, identifier):
        return self._desktop.check(identifier)

    @bridge_action
    def start(self, identifier, action, payload=None):
        return self._desktop.start(identifier, action, payload)

    @bridge_action
    def stop(self):
        return self._desktop.stop()

    @bridge_action
    def open_received(self, identifier):
        folder = Path(self._desktop._profile(identifier)["receive_dir"])
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        if sys.platform == "win32":
            os.startfile(folder)
        else:
            subprocess.Popen(
                ["/usr/bin/open" if sys.platform == "darwin" else "xdg-open", str(folder)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        return str(folder)

    @bridge_action
    def export_trace(self):
        import webview

        result = self._desktop.window.create_file_dialog(
            webview.FileDialog.SAVE,
            save_filename="pingo-trace.jsonl",
            file_types=("JSON lines (*.jsonl)",),
        )
        if not result:
            return None
        with self._desktop.lock:
            text = "".join(json.dumps(item) + "\n" for item in self._desktop.events)
        atomic_write(Path(result[0]), text)
        return str(result[0])

    @bridge_action
    def elevate(self):
        self._desktop._idle()
        if sys.platform != "win32":
            raise ValueError(
                "On macOS/Linux, close Pingo and launch pingo-gui with sudo/root privileges."
            )
        if elevated():
            return False
        args = ["--data-dir", str(self._desktop.root)]
        if not getattr(sys, "frozen", False):
            args = ["-m", "pingo.desktop", *args]
        execute = ctypes.windll.shell32.ShellExecuteW
        execute.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        execute.restype = ctypes.c_void_p
        result = execute(None, "runas", sys.executable, subprocess.list2cmdline(args), None, 1)
        if not result or result <= 32:
            raise OSError("Administrator restart was cancelled or could not start.")
        self._desktop.window.destroy()
        return True


def page_html():
    directory = Path(__file__).parent / "ui"
    html = (directory / "index.html").read_text(encoding="utf-8")
    return html.replace(
        '<link rel="stylesheet" href="app.css" />',
        "<style>" + (directory / "app.css").read_text(encoding="utf-8") + "</style>",
    ).replace(
        '<script src="app.js" defer></script>',
        "<script>" + (directory / "app.js").read_text(encoding="utf-8") + "</script>",
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pingo desktop")
    parser.add_argument(
        "--data-dir", type=Path, help="override the local connection storage directory"
    )
    parser.add_argument("--smoke-test", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        import webview
    except ImportError:
        startup_error('Install desktop support: python -m pip install "pingo-tunnel[gui]"')
        return 1
    if args.smoke_test:
        from .desktop_smoke import run

        return run(args.smoke_test)
    try:
        desktop = Desktop(args.data_dir)
        webview.settings["ALLOW_DOWNLOADS"] = False
        webview.settings["ALLOW_FILE_URLS"] = False
        window = webview.create_window(
            "Pingo",
            html=page_html(),
            js_api=Api(desktop),
            width=1180,
            height=900,
            min_size=(760, 620),
            background_color="#f3f4f6",
            text_select=True,
        )
        desktop.window = window
        window.events.closing += desktop.closing
        webview.start(gui="edgechromium" if sys.platform == "win32" else None)
    except Exception as exc:
        startup_error(
            f"Pingo could not open its desktop window.\n\n{exc}\n\n"
            "On Windows, check that Microsoft Edge WebView2 Runtime is installed. "
            "On macOS, use a Python installation with pywebview's Cocoa dependencies. "
            "On Linux, install a pywebview GTK or Qt backend."
        )
        return 1
    return 0


def startup_error(message):
    if sys.stderr is not None:
        print(message, file=sys.stderr)
    if sys.platform == "win32":
        ctypes.windll.user32.MessageBoxW(None, message, "Pingo could not start", 0x10)


if __name__ == "__main__":
    raise SystemExit(main())
