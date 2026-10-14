"""Darwin packet capture, utun, and reversible system network configuration."""

import ctypes as c
import ipaddress
import json
import logging
import os
import re
import select
import socket
import struct
import subprocess
import sys
import uuid
from pathlib import Path

from .crypto import PacketError
from .icmp import decode
from .vpn import MTU

LOG = logging.getLogger(__name__)
ROUTE, IFCONFIG = "/sbin/route", "/sbin/ifconfig"
PFCTL, NETWORKSETUP = "/sbin/pfctl", "/usr/sbin/networksetup"
PF_STATE_DIRECTORY = Path("/var/run/pingo")
DNS_STATE_DIRECTORY = Path("/Library/Application Support/Pingo/Recovery")


def command(args, data=None):
    result = subprocess.run(
        args,
        input=data,
        text=True,
        capture_output=True,
        check=True,
        timeout=15,
        env={**os.environ, "LC_ALL": "C"},
    )
    return result.stdout + (result.stderr if args == [PFCTL, "-E"] else "")


def route_info(peer, runner=command):
    output = runner([ROUTE, "-n", "get", "-inet", str(ipaddress.IPv4Address(peer))])
    fields = {}
    for line in output.splitlines():
        key, separator, value = line.strip().partition(":")
        if separator:
            fields[key] = value.strip()
    interface = fields.get("interface", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        raise ValueError("cannot identify the macOS endpoint interface")
    return fields


class Timeval(c.Structure):
    _fields_ = [("seconds", c.c_int64), ("microseconds", c.c_int32)]


class CaptureHeader(c.Structure):
    _fields_ = [("timestamp", Timeval), ("captured", c.c_uint32), ("length", c.c_uint32)]


class BPFProgram(c.Structure):
    _fields_ = [("length", c.c_uint32), ("instructions", c.c_void_p)]


def capture_ipv4(frame, link):
    if link == 1:  # Ethernet, with bounded 802.1Q/QinQ tags.
        offset = 14
        if len(frame) < offset:
            raise PacketError("short Ethernet capture")
        protocol = int.from_bytes(frame[12:14], "big")
        for _ in range(2):
            if protocol not in (0x8100, 0x88A8):
                break
            if len(frame) < offset + 4:
                raise PacketError("short VLAN capture")
            protocol = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
        if protocol != 0x0800:
            raise PacketError("capture is not IPv4")
        frame = frame[offset:]
    elif link in (0, 108):  # DLT_NULL / DLT_LOOP.
        order = sys.byteorder if link == 0 else "big"
        if len(frame) < 4 or int.from_bytes(frame[:4], order) != socket.AF_INET:
            raise PacketError("capture is not IPv4 loopback")
        frame = frame[4:]
    elif link not in (12, 101):  # Darwin DLT_RAW / LINKTYPE_RAW.
        raise PacketError("unsupported macOS capture link type")
    if len(frame) < 20:
        raise PacketError("short captured IPv4 packet")
    length = int.from_bytes(frame[2:4], "big")
    if not 20 <= length <= len(frame):
        raise PacketError("truncated captured IPv4 packet")
    return frame[:length]  # Ethernet padding is outside the IP datagram.


class MacCapture:
    """Capture echo requests before Darwin's ICMP responder consumes them."""

    def __init__(self, peer, bind="0.0.0.0", library=None, runner=command):
        self.peer = str(ipaddress.IPv4Address(peer))
        self.bind = str(ipaddress.IPv4Address(bind))
        self.lib = library or c.CDLL("/usr/lib/libpcap.A.dylib")
        signatures = {
            "pcap_open_live": ([c.c_char_p, c.c_int, c.c_int, c.c_int, c.c_char_p], c.c_void_p),
            "pcap_compile": (
                [c.c_void_p, c.POINTER(BPFProgram), c.c_char_p, c.c_int, c.c_uint32],
                c.c_int,
            ),
            "pcap_setfilter": ([c.c_void_p, c.POINTER(BPFProgram)], c.c_int),
            "pcap_freecode": ([c.POINTER(BPFProgram)], None),
            "pcap_setnonblock": ([c.c_void_p, c.c_int, c.c_char_p], c.c_int),
            "pcap_get_selectable_fd": ([c.c_void_p], c.c_int),
            "pcap_datalink": ([c.c_void_p], c.c_int),
            "pcap_next_ex": (
                [c.c_void_p, c.POINTER(c.POINTER(CaptureHeader)), c.POINTER(c.c_void_p)],
                c.c_int,
            ),
            "pcap_geterr": ([c.c_void_p], c.c_char_p),
            "pcap_close": ([c.c_void_p], None),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = args, result
        interface = route_info(self.peer, runner)["interface"]
        error = c.create_string_buffer(256)
        self.handle = self.lib.pcap_open_live(interface.encode(), 65535, 0, 50, error)
        if not self.handle:
            raise OSError(
                "macOS capture requires root/BPF access: " + error.value.decode(errors="replace")
            )
        try:
            self.link = self.lib.pcap_datalink(self.handle)
            if self.link not in (0, 1, 12, 101, 108):
                raise OSError(f"unsupported capture link type: {self.link}")
            expression = f"icmp and src host {self.peer} and icmp[0] = 8 and icmp[4:2] = 0x5047"
            if self.bind != "0.0.0.0":
                expression += f" and dst host {self.bind}"
            program = BPFProgram()
            if self.lib.pcap_compile(
                self.handle, c.byref(program), expression.encode(), 1, 0xFFFFFFFF
            ):
                self._error()
            try:
                if self.lib.pcap_setfilter(self.handle, c.byref(program)):
                    self._error()
            finally:
                self.lib.pcap_freecode(c.byref(program))
            if self.lib.pcap_setnonblock(self.handle, 1, error):
                self._error()
            self.fd = self.lib.pcap_get_selectable_fd(self.handle)
            if self.fd < 0:
                raise OSError("macOS capture does not provide a selectable descriptor")
        except BaseException:
            self.close()
            raise

    def _error(self):
        message = self.lib.pcap_geterr(self.handle) or b"capture failed"
        raise OSError(message.decode(errors="replace"))

    def recv(self, timeout):
        # libpcap may retain buffered packets after its descriptor stops being readable.
        header, data = c.POINTER(CaptureHeader)(), c.c_void_p()
        result = self.lib.pcap_next_ex(self.handle, c.byref(header), c.byref(data))
        if result == 0 and select.select([self.fd], [], [], timeout)[0]:
            result = self.lib.pcap_next_ex(self.handle, c.byref(header), c.byref(data))
        if result == 0:
            return None
        if result < 0:
            self._error()
        if not header or not data or not 0 < header.contents.captured <= 65535:
            raise OSError("invalid packet capture length")
        try:
            frame = c.string_at(data, header.contents.captured)
            packet = capture_ipv4(frame, self.link)
            if self.bind != "0.0.0.0" and str(ipaddress.IPv4Address(packet[16:20])) != self.bind:
                return None
            return decode(packet, self.peer)
        except PacketError:
            return None

    def close(self):
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None


class Utun:
    def __init__(self, name="pingo0", factory=socket.socket, ioctl=None):
        if sys.platform != "darwin" and ioctl is None:
            raise OSError("utun requires macOS")
        if name in ("pingo0", "utun", "auto"):
            unit = 0
        elif re.fullmatch(r"utun[0-9]{1,4}", name):
            unit = int(name[4:]) + 1
        else:
            raise ValueError("macOS interface must be 'auto' or utun followed by a number")
        if ioctl is None:
            from fcntl import ioctl
        self.socket = factory(getattr(socket, "AF_SYSTEM", 32), socket.SOCK_DGRAM, 2)
        try:
            info = ioctl(
                self.socket.fileno(),
                0xC0644E03,
                struct.pack("=I96s", 0, b"com.apple.net.utun_control"),
            )
            control = struct.unpack_from("=I", info)[0]
            self.socket.connect((control, unit))
            self.name = self.socket.getsockopt(2, 2, 16).split(b"\0", 1)[0].decode("ascii")
            if not re.fullmatch(r"utun[0-9]{1,4}", self.name):
                raise OSError("kernel returned an invalid utun name")
            self.socket.setblocking(False)
        except BaseException:
            self.close()
            raise

    def read(self, timeout=0.2):
        if not select.select([self.socket], [], [], timeout)[0]:
            return None
        try:
            frame = self.socket.recv(65539)
        except BlockingIOError:
            return None
        if len(frame) < 4 or struct.unpack_from("!I", frame)[0] != socket.AF_INET:
            return None
        return frame[4:]

    def write(self, packet):
        frame = struct.pack("!I", socket.AF_INET) + packet
        try:
            if self.socket.send(frame) != len(frame):
                raise OSError("partial utun packet write")
        except BlockingIOError:
            pass

    def close(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class MacRoutes:
    def __init__(self, peer, interface, address, routes=(), default=False, runner=command):
        self.peer = str(ipaddress.IPv4Address(peer))
        self.address = ipaddress.IPv4Interface(address)
        if ipaddress.IPv4Address(peer) in self.address.network:
            raise ValueError("utun subnet must not contain the outer peer address")
        if not re.fullmatch(r"utun[0-9]{1,4}", interface):
            raise ValueError("invalid utun interface")
        self.interface, self.runner, self.undo = interface, runner, []
        self.routes = [str(ipaddress.IPv4Network(route)) for route in routes]
        if any(ipaddress.IPv4Network(route).prefixlen == 0 for route in self.routes):
            raise ValueError("use --default-route for a default route")
        if len(self.routes) > 32 or len(set(self.routes)) != len(self.routes):
            raise ValueError("at most 32 distinct routes are allowed")
        if default:
            self.routes.extend(["0.0.0.0/1", "128.0.0.0/1"])
        if len(set(self.routes)) != len(self.routes):
            raise ValueError("duplicate route")

    def _add(self, arguments):
        self.runner([ROUTE, "-n", "add", "-inet", *arguments])
        self.undo.append([ROUTE, "-n", "delete", "-inet", *arguments])

    def __enter__(self):
        try:
            original = route_info(self.peer, self.runner)
            outer = original["interface"]
            if outer == self.interface or outer.startswith("utun") or outer == "lo0":
                raise ValueError("outer peer must use a separate physical network interface")
            if self.routes:
                if "HOST" not in original.get("flags", ""):
                    gateway = original.get("gateway", "")
                    try:
                        gateway = str(ipaddress.IPv4Address(gateway))
                    except ipaddress.AddressValueError:
                        if "GATEWAY" in original.get("flags", ""):
                            raise ValueError("cannot identify the original IPv4 gateway") from None
                        gateway = None
                    arguments = ["-host", self.peer]
                    arguments += [gateway] if gateway else ["-interface", outer]
                    self._add(arguments)
            self.runner(
                [
                    IFCONFIG,
                    self.interface,
                    "inet",
                    str(self.address.ip),
                    str(self.address.ip),
                    "netmask",
                    str(self.address.netmask),
                    "mtu",
                    str(MTU),
                    "up",
                ]
            )
            self.undo.append([IFCONFIG, self.interface, "inet", str(self.address.ip), "-alias"])
            self._add(["-net", str(self.address.network), "-interface", self.interface])
            for prefix in self.routes:
                if prefix != str(self.address.network):
                    self._add(["-net", prefix, "-interface", self.interface])
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        failures = []
        while self.undo:
            arguments = self.undo.pop()
            try:
                self.runner(arguments)
            except (OSError, subprocess.SubprocessError) as exc:
                LOG.error("macOS route cleanup failed: %s; command: %s", exc, arguments)
                failures.append(arguments)
        if failures:
            raise OSError("macOS route cleanup incomplete; recovery commands were logged")

    def __exit__(self, *_):
        self.close()


def save_state(path, value):
    encoded = json.dumps(value, allow_nan=False)
    if len(encoded.encode("utf-8")) > 65536:
        raise ValueError("macOS recovery record exceeds 64 KiB")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.parent.lstat()
    if path.parent.is_symlink() or (
        os.name == "posix" and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077)
    ):
        raise PermissionError("macOS recovery directory must be private and owned by this user")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def dns_servers(service, runner):
    output = runner([NETWORKSETUP, "-getdnsservers", service]).strip()
    if output.startswith("There aren't any DNS Servers set on "):
        return []
    values = output.splitlines()
    if not values or len(values) > 32:
        raise ValueError("cannot read the current macOS DNS configuration")
    return [str(ipaddress.ip_address(value.strip())) for value in values]


def restore_dns(record, runner):
    if not isinstance(record, dict) or set(record) != {"servers", "services"}:
        raise ValueError("invalid macOS DNS recovery record")
    servers, entries = record["servers"], record["services"]
    if (
        not isinstance(servers, list)
        or not 1 <= len(servers) <= 32
        or not isinstance(entries, list)
        or not 1 <= len(entries) <= 100
    ):
        raise ValueError("invalid macOS DNS recovery record")
    servers = [str(ipaddress.IPv4Address(value)) for value in servers]
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"name", "before"}:
            raise ValueError("invalid macOS DNS recovery service")
        service = entry["name"]
        if (
            not isinstance(service, str)
            or not service
            or len(service) > 256
            or service.startswith("-")
            or "\0" in service
            or "\n" in service
            or "\r" in service
        ):
            raise ValueError("invalid macOS network service")
        if not isinstance(entry["before"], list) or len(entry["before"]) > 32:
            raise ValueError("invalid saved macOS DNS servers")
        for value in entry["before"]:
            ipaddress.ip_address(value)
    failures = []
    for entry in reversed(entries):
        service = entry["name"]
        before = [str(ipaddress.ip_address(value)) for value in entry["before"]]
        try:
            current = dns_servers(service, runner)
            if current == servers:
                runner([NETWORKSETUP, "-setdnsservers", service, *(before or ["Empty"])])
            elif current != before:
                LOG.warning("DNS for %s changed outside Pingo; leaving it unchanged", service)
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(exc)
    if failures:
        raise OSError("macOS DNS cleanup incomplete; run pingo unlock")


class MacDNS:
    def __init__(self, interface, servers, runner=command, state_directory=DNS_STATE_DIRECTORY):
        self.runner = runner
        self.servers = [str(ipaddress.IPv4Address(value)) for value in servers]
        self.path = Path(state_directory) / ("dns-" + uuid.uuid4().hex + ".json")
        self.record = None

    def __enter__(self):
        if any(self.path.parent.glob("dns-*.json")):
            raise ValueError("previous Pingo DNS changes need recovery; run pingo unlock first")
        names = self.runner([NETWORKSETUP, "-listallnetworkservices"]).splitlines()
        names = [name.strip() for name in names[1:] if name.strip() and not name.startswith("*")]
        if not names or len(names) > 100:
            raise ValueError("cannot identify enabled macOS network services")
        entries = [{"name": name, "before": dns_servers(name, self.runner)} for name in names]
        self.record = {"servers": self.servers, "services": entries}
        save_state(self.path, self.record)
        try:
            for name in names:
                self.runner([NETWORKSETUP, "-setdnsservers", name, *self.servers])
                if dns_servers(name, self.runner) != self.servers:
                    raise OSError(f"macOS did not apply DNS to {name}")
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.record is not None:
            restore_dns(self.record, self.runner)
            self.path.unlink(missing_ok=True)
            self.record = None

    def __exit__(self, *_):
        self.close()


def remove_pf(record, runner):
    if not isinstance(record, dict) or set(record) != {"anchor", "token"}:
        raise ValueError("invalid Pingo PF recovery record")
    anchor, token = record["anchor"], record["token"]
    if not re.fullmatch(r"com\.apple/000\.Pingo_[0-9a-f]{32}", anchor):
        raise ValueError("invalid Pingo PF recovery anchor")
    if not isinstance(token, str) or not re.fullmatch(r"[0-9]{1,20}", token):
        raise ValueError("invalid Pingo PF enable token")
    runner([PFCTL, "-a", anchor, "-F", "rules"])
    runner([PFCTL, "-X", token])


class MacKillSwitch:
    """An early PF anchor; never replace the host's root ruleset or disable PF."""

    def __init__(self, peer, interface, runner=command, state_directory=PF_STATE_DIRECTORY):
        self.peer = str(ipaddress.IPv4Address(peer))
        if not re.fullmatch(r"utun[0-9]{1,4}", interface):
            raise ValueError("invalid utun interface")
        self.interface, self.runner = interface, runner
        identifier = uuid.uuid4().hex
        self.anchor = "com.apple/000.Pingo_" + identifier
        self.path = Path(state_directory) / ("pf-" + identifier + ".json")
        self.record = None

    def rules(self):
        return (
            "pass quick on lo0 all no state\n"
            f"pass quick on {self.interface} inet all no state\n"
            f"pass out quick inet proto icmp to {self.peer} "
            "icmp-type { echoreq, echorep } no state\n"
            f"pass in quick inet proto icmp from {self.peer} "
            "icmp-type { echoreq, echorep } no state\n"
            "block drop quick all\n"
        )

    def __enter__(self):
        if any(self.path.parent.glob("pf-*.json")):
            raise ValueError("previous Pingo PF protection needs recovery; run pingo unlock first")
        root = [line.strip() for line in self.runner([PFCTL, "-sr"]).splitlines() if line.strip()]
        if 'anchor "com.apple/*" all' not in root or any(
            line != 'anchor "com.apple/*" all' and not line.startswith('scrub-anchor "com.apple/*"')
            for line in root
        ):
            raise ValueError(
                "macOS kill switch requires the standard com.apple/* PF hook; "
                "custom or unloaded root rules are refused"
            )
        anchors = self.runner([PFCTL, "-a", "com.apple", "-s", "Anchors"]).splitlines()
        live_anchors = []
        for name in anchors:
            child = name.strip().strip('"').rsplit("/", 1)[-1]
            if child.startswith("000.Pingo_"):
                if self.runner([PFCTL, "-a", "com.apple/" + child, "-sr"]).strip():
                    raise ValueError("Pingo protection already exists; run pingo unlock first")
            elif child:
                live_anchors.append(child)
        if any(child < self.anchor.split("/")[1] for child in live_anchors):
            raise ValueError("an earlier PF anchor prevents safe Pingo kill-switch ordering")
        current = ""
        for line in self.runner([PFCTL, "-s", "Interfaces", "-v"]).splitlines():
            if line and not line[0].isspace():
                current = line.split()[0].rstrip(":")
            if re.search(r"\bskip\b", line, re.I) and current != "lo0":
                raise ValueError("PF skips a non-loopback interface; kill-switch setup refused")
        rules = self.rules()
        self.runner([PFCTL, "-n", "-a", self.anchor, "-f", "-"], rules)
        output = self.runner([PFCTL, "-E"])
        token = re.search(r"Token\s*:\s*([0-9]+)", output)
        if not token:
            raise OSError("PF did not return an owned enable token")
        self.record = {"anchor": self.anchor, "token": token.group(1)}
        try:
            save_state(self.path, self.record)
        except BaseException:
            self.runner([PFCTL, "-X", self.record["token"]])
            self.record = None
            raise
        try:
            self.runner([PFCTL, "-a", self.anchor, "-f", "-"], rules)
            # Established PF states bypass new filters; clear them only for an explicit guard.
            self.runner([PFCTL, "-F", "states"])
        except BaseException:
            LOG.error("Pingo PF protection may be retained; recover with: pingo unlock")
            raise
        LOG.info("macOS kill switch active (existing PF connections reset); recovery: pingo unlock")
        return self

    def close(self):
        if self.record is not None:
            remove_pf(self.record, self.runner)
            self.path.unlink(missing_ok=True)
            self.record = None

    def __exit__(self, kind, *_):
        if kind is None:
            self.close()
        else:
            LOG.error("macOS kill switch retained after failure; recover with: pingo unlock")


def unlock_macos(runner=command, state_directory=None):
    if state_directory is None:
        unlock_macos(runner, DNS_STATE_DIRECTORY)
        unlock_macos(runner, PF_STATE_DIRECTORY)
        return
    directory = Path(state_directory)
    if not directory.exists():
        return
    metadata = directory.lstat()
    if directory.is_symlink() or (
        os.name == "posix" and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077)
    ):
        raise PermissionError("untrusted macOS recovery directory")
    for path in sorted(directory.glob("*.json")):
        if not re.fullmatch(r"(dns|pf)-[0-9a-f]{32}\.json", path.name):
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError("invalid macOS recovery record")
        record = json.loads(path.read_text(encoding="utf-8"))
        if path.name.startswith("dns-"):
            restore_dns(record, runner)
        else:
            expected = "com.apple/000.Pingo_" + path.stem[3:]
            if record.get("anchor") != expected:
                raise ValueError("PF recovery identity mismatch")
            remove_pf(record, runner)
        path.unlink()
