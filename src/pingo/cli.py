import argparse
import ipaddress
import json
import logging
import signal
import subprocess
import sys
import threading
from contextlib import ExitStack
from pathlib import Path

from . import __version__
from .config import Config, generate_key
from .direct import CHUNK, END, send_file, send_message
from .icmp import RawICMP
from .reconnect import Connector, recoverable
from .reliable import Reliable
from .resume import RESUME, ResumableReceiver, send_resumable
from .traffic import TracedCarrier, Traffic
from .transport import Endpoint
from .vpn import VPN, Routes, Tun


def parser():
    result = argparse.ArgumentParser(prog="pingo", description="Experimental encrypted ICMP tunnel")
    result.add_argument("--version", action="version", version=f"Pingo {__version__}")
    commands = result.add_subparsers(dest="command", required=True)
    gui = commands.add_parser("gui", help="open the desktop app (install the gui extra)")
    gui.add_argument("--data-dir", type=Path, help="local desktop connection storage directory")
    keygen = commands.add_parser(
        "keygen", help="create a private 32-byte shared key (no overwrite)"
    )
    keygen.add_argument("path", type=Path)
    unlock = commands.add_parser("unlock", help="remove Pingo's retained crash kill switch")
    unlock.add_argument("--table", help="Linux nft table identity printed at startup")
    descriptions = {
        "listen": "receive messages and files from your peer",
        "message": "send a text message to your peer",
        "file": "send a file, resuming an interrupted transfer",
        "vpn": "connect an IPv4 VPN or wait as its responder",
    }
    for name, description in descriptions.items():
        command = commands.add_parser(name, help=description, description=description)
        command.add_argument("--config", type=Path, required=True)
        command.add_argument(
            "--traffic",
            choices=("off", "summary", "hex"),
            default="hex",
            help="live packet JSON on stderr (default: full wire hex)",
        )
        command.add_argument(
            "--reconnects",
            type=int,
            choices=range(21),
            default=10,
            metavar="0..20",
            help="bounded automatic reconnection attempts",
        )
        if name == "listen":
            command.add_argument(
                "--resume-retention",
                type=int,
                default=86400,
                help="retain resumable checkpoints for this many seconds",
            )
        if name == "message":
            command.add_argument("text")
        elif name == "file":
            command.add_argument("path", type=Path)
            command.add_argument("--no-resume", action="store_true", help="use legacy transfers")
        elif name == "vpn":
            command.add_argument("--listen", action="store_true", help="act as responder")
            command.add_argument(
                "--interface",
                default="pingo0",
                help="adapter name (macOS: auto or a fresh utunN; pingo0 means auto)",
            )
            command.add_argument("--address", required=True, help="local TUN IPv4 CIDR")
            command.add_argument(
                "--wintun-dll",
                type=Path,
                help="Windows: explicit path to signed official wintun.dll",
            )
            command.add_argument(
                "--dns",
                action="append",
                default=[],
                metavar="IPv4",
                help="configure tunnel DNS (default route: 1.1.1.1)",
            )
            command.add_argument("--no-dns", action="store_true", help="leave system DNS alone")
            command.add_argument(
                "--kill-switch",
                action=argparse.BooleanOptionalAction,
                default=None,
                help="block outside traffic; default with default route; macOS resets PF states",
            )
            command.add_argument("--route", action="append", default=[], help="selected IPv4 CIDR")
            command.add_argument(
                "--default-route",
                action="store_true",
                help="route default IPv4 traffic using two /1 routes",
            )
            command.add_argument(
                "--allowed-source",
                action="append",
                default=[],
                help="allowed inner peer source CIDR; default: TUN subnet",
            )
    return result


def run_listener(factory, config, args, stop, events=None):
    events = events or (lambda *_args, **_kwargs: None)
    if not 60 <= args.resume_retention <= 604800:
        raise ValueError("resume retention must be 60..604800 seconds")
    receiver = ResumableReceiver(
        config.receive_dir,
        config.max_file_bytes,
        config.max_receive_bytes,
        on_message=lambda text: events("message", text=text),
        retention_seconds=args.resume_retention,
    )
    try:
        for failure in range(args.reconnects + 1):
            try:
                with factory() as endpoint:
                    channel = Reliable(
                        endpoint, attempts=config.attempts, timeout=config.retry_seconds
                    )
                    receiver.attach(channel)

                    def handle(data):
                        state = receiver.active
                        result = receiver.handle(data)
                        if data and data[0] == END and state:
                            events("received_file", name=result.decode("ascii"), size=state["size"])
                            events(
                                "progress",
                                done=state["size"],
                                total=state["size"],
                                phase="verified",
                                name=state["name"],
                            )
                        elif data and data[0] in (CHUNK, RESUME) and receiver.active:
                            current = receiver.active
                            events(
                                "progress",
                                done=current["offset"],
                                total=current["size"],
                                phase="receiving",
                                name=current["name"],
                            )
                        return result

                    channel.handler = handle
                    endpoint.start(responder=True)
                    events("state", state="listening")
                    logging.info(
                        "Listening for %s; files go to %s", config.peer, config.receive_dir
                    )
                    while not stop.wait(0.2):
                        endpoint.check()
                    return
            except (OSError, RuntimeError) as exc:
                receiver.suspend()
                if not recoverable(exc) or failure == args.reconnects:
                    raise
                if stop.wait(min(0.5 * 2 ** min(failure, 5), 10)):
                    return
                logging.warning("Restarting listener after transport failure")
    finally:
        receiver.suspend()


def run_vpn(factory, config, args, stop, traffic, events=None):
    events = events or (lambda *_args, **_kwargs: None)
    from .network import LinuxDNS, LinuxKillSwitch, WindowsDNS
    from .windows import WindowsRoutes, Wintun

    address = ipaddress.IPv4Interface(args.address)
    allowed = args.allowed_source or [str(address.network)]
    for network in allowed:
        ipaddress.IPv4Network(network)
    if args.no_dns and args.dns:
        raise ValueError("--dns and --no-dns are mutually exclusive")
    dns = [] if args.no_dns else args.dns or (["1.1.1.1"] if args.default_route else [])
    for server in dns:
        value = ipaddress.IPv4Address(server)
        if (
            value.is_unspecified
            or value.is_multicast
            or value.is_loopback
            or int(value) == 0xFFFFFFFF
            or str(value) == config.peer
        ):
            raise ValueError("DNS must be a unicast IPv4 resolver different from the outer peer")
    kill = args.kill_switch if args.kill_switch is not None else args.default_route
    if args.listen and kill:
        raise ValueError("kill switch is for VPN clients; omit it on the exit/responder")
    if sys.platform == "win32" and args.wintun_dll is None:
        raise ValueError("Windows VPN requires --wintun-dll pointing to signed official wintun.dll")
    if sys.platform not in ("win32", "linux", "darwin"):
        raise OSError("VPN requires Linux TUN, Windows Wintun, or macOS utun")
    selected = list(args.route)
    for server in dns:
        prefix = str(ipaddress.IPv4Address(server)) + "/32"
        if prefix not in selected and ipaddress.IPv4Address(server) not in address.network:
            selected.append(prefix)
    routes_class = WindowsRoutes if sys.platform == "win32" else Routes
    dns_class = WindowsDNS if sys.platform == "win32" else LinuxDNS
    if sys.platform == "darwin":
        from .macos import MacDNS, MacKillSwitch, MacRoutes, Utun

        routes_class, dns_class = MacRoutes, MacDNS
    with ExitStack() as stack:
        tun = stack.enter_context(
            Wintun(args.interface, args.wintun_dll)
            if sys.platform == "win32"
            else Utun(args.interface)
            if sys.platform == "darwin"
            else Tun(args.interface)
        )
        routes = routes_class(config.peer, tun.name, args.address, selected, args.default_route)
        if kill:
            if sys.platform == "win32":
                from .wfp import WindowsKillSwitch

                guard = WindowsKillSwitch(config.peer, tun)
            elif sys.platform == "darwin":
                guard = MacKillSwitch(config.peer, tun.name)
            else:
                guard = LinuxKillSwitch(config.peer, tun.name)
            stack.enter_context(guard)
        configured = False
        for failure in range(args.reconnects + 1):
            if stop.is_set():
                return
            try:
                with factory() as endpoint:
                    vpn = VPN(endpoint, tun, allowed, traffic=traffic)
                    endpoint.on_session = vpn.reset
                    if args.listen:
                        endpoint.start(responder=True)
                        logging.info("Waiting for authenticated VPN peer")
                        events("state", state="listening")
                        while not stop.is_set() and not endpoint.ready.wait(0.2):
                            endpoint.check()
                        if stop.is_set():
                            return
                    else:
                        events("state", state="connecting")
                        endpoint.connect(config.attempts, config.retry_seconds, stop=stop)
                        endpoint.start()
                    if not configured:
                        stack.enter_context(routes)
                        if dns:
                            stack.enter_context(dns_class(tun.name, dns))
                        configured = True
                    logging.info("VPN ready on %s (%s); IPv4 MTU 1000", tun.name, address)
                    events("state", state="connected")
                    vpn.run(stop)
                    return
            except OSError as exc:
                if not recoverable(exc) or failure == args.reconnects:
                    raise
                delay = min(0.5 * 2 ** min(failure, 5), 10)
                logging.warning("VPN peer unavailable; reconnecting in %.1fs", delay)
                events("state", state="reconnecting", delay=delay, attempt=failure + 1)
                if stop.wait(delay):
                    return
            except InterruptedError:
                if stop.is_set():
                    return
                raise


def main(argv=None, events=None, stop=None):
    args = parser().parse_args(argv)
    if args.command == "gui":
        from .desktop import main as desktop_main

        return desktop_main(["--data-dir", str(args.data_dir)] if args.data_dir else [])
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    stop = stop if stop is not None else threading.Event()
    desktop_events = events

    def emit(kind, **fields):
        if desktop_events:
            desktop_events(kind, **fields)
        elif kind == "message":
            print(json.dumps({"message": fields["text"]}), flush=True)

    previous = {}
    traffic = None

    def halt(*_):
        stop.set()
        if args.command in ("message", "file"):
            raise KeyboardInterrupt

    try:
        if args.command == "keygen":
            generate_key(args.path)
            print(f"Created {args.path}; securely copy this same key to the other peer.")
            return 0
        if args.command == "unlock":
            if sys.platform == "win32":
                from .network import cleanup_windows_dns
                from .wfp import unlock_windows

                unlock_windows()
                cleanup_windows_dns()
            elif sys.platform == "darwin":
                from .macos import unlock_macos

                unlock_macos()
            else:
                from .network import unlock_linux

                unlock_linux(args.table)
            print("Removed Pingo kill switch.")
            return 0
        config = Config.load(args.config)
        key = config.key()
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, halt)
        mode = "vpn" if args.command == "vpn" else "direct"
        traffic = Traffic(args.traffic)

        def factory():
            return Endpoint(
                TracedCarrier(RawICMP(config.peer, config.bind), traffic, config.peer),
                key,
                mode,
                persistent=True,
            )

        if args.command == "vpn":
            run_vpn(factory, config, args, stop, traffic, emit)
        elif args.command == "listen":
            run_listener(factory, config, args, stop, emit)
        else:
            with Connector(
                factory, stop, config.attempts, config.retry_seconds, args.reconnects, emit
            ) as channel:
                if args.command == "message":
                    result = send_message(channel, args.text)
                    emit("sent_message", text=args.text, result=result)
                    if not desktop_events:
                        print(result, flush=True)
                else:
                    if args.no_resume:
                        name = send_file(channel, args.path, config.max_file_bytes)
                    else:
                        name = send_resumable(
                            channel,
                            args.path,
                            config.max_file_bytes,
                            reconnects=args.reconnects,
                            progress=lambda done, total, phase: emit(
                                "progress", done=done, total=total, phase=phase, name=args.path.name
                            ),
                        )
                    emit("sent_file", name=name)
                    if not desktop_events:
                        print("Verified receiver file: " + name, flush=True)
        return 0
    except KeyboardInterrupt:
        return 130
    except InterruptedError:
        return 130
    except subprocess.SubprocessError as exc:
        logging.error("network setup failed: %s", getattr(exc, "stderr", None) or str(exc))
        return 1
    except (OSError, ValueError, RuntimeError, OverflowError) as exc:
        logging.error("%s", exc)
        return 1
    finally:
        if traffic is not None:
            traffic.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
