"""Opt-in native WebView smoke check; uses test storage and never sends network packets."""

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from .desktop import Api, Desktop, page_html
from .handshake import InitiatorHandshake, respond


def run(result_path):
    import webview

    result_path = Path(result_path).resolve()
    result_path.parent.mkdir(parents=True, exist_ok=True)
    desktop = Desktop(result_path.parent / ("smoke-data-" + str(time.time_ns())))
    window = webview.create_window(
        "Pingo interface verification",
        html=page_html(),
        js_api=Api(desktop),
        width=1180,
        height=850,
        hidden=True,
    )
    desktop.window = window
    loaded = threading.Event()
    window.events.loaded += loaded.set
    results = {"passed": False, "checks": []}

    def wait_for(expression):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if window.evaluate_js(expression):
                return
            time.sleep(0.1)
        raise AssertionError("Timed out: " + expression)

    def check(name, expression):
        if not window.evaluate_js(expression):
            raise AssertionError(name)
        results["checks"].append(name)

    def verify():
        try:
            handshake = InitiatorHandshake(bytes(range(32)), b"D")
            responder, response = respond(bytes(range(32)), b"D", handshake.hello)
            initiator = handshake.accept(bytes(range(32)), response)
            assert responder.decrypt(initiator.encrypt(b"native smoke")) == b"native smoke"
            assert initiator.decrypt(responder.encrypt(b"reply")) == b"reply"
            results["checks"].append("Bundled Noise handshake and AEAD (no networking)")
            assert loaded.wait(20), "WebView did not load"
            wait_for("document.getElementById('status').textContent === 'Setup needed'")
            results["checks"].append("Native HTML and Python bridge loaded")
            window.evaluate_js("document.getElementById('new-connection').click()")
            check("Setup dialog opened", "document.getElementById('connection-dialog').open")
            window.evaluate_js("""
                document.getElementById('profile-name').value='Smoke peer';
                document.getElementById('profile-peer').value='192.0.2.20';
                document.getElementById('profile-bind').value='192.0.2.10';
                document.getElementById('generate-key').click();
            """)
            wait_for("document.getElementById('profile-key').value.length > 0")
            window.evaluate_js("document.getElementById('connection-form').requestSubmit()")
            wait_for("!document.getElementById('connection-dialog').open")
            check(
                "Native key generation and saved connection",
                """
                document.getElementById('peer-ip').textContent === '192.0.2.20' &&
                !document.getElementById('receive').disabled
            """,
            )
            desktop._event({"event": "message", "text": "<script>window.injected=true</script>"})
            desktop._event(
                {
                    "event": "traffic",
                    "direction": "tx",
                    "layer": "icmp",
                    "bytes": 4,
                    "bytes_total": 4,
                    "packets_total": 1,
                    "bytes_per_second": 4,
                    "wire_hex": "0123abcd",
                }
            )
            wait_for("document.querySelector('#trace pre') !== null")
            check(
                "Hex trace remains visible",
                """
                document.querySelector('#trace pre').textContent === '01 23 ab cd' &&
                document.getElementById('show-hex').checked
            """,
            )
            check(
                "Peer messages render as text",
                """
                !window.injected &&
                document.getElementById('activity').textContent.includes('<script>')
            """,
            )
            window.evaluate_js(
                "document.querySelector('[data-view=check]').click(); "
                "document.getElementById('setup-results').open=true; "
                "document.getElementById('run-check').click()"
            )
            wait_for("document.querySelectorAll('.check-row').length >= 5")
            check("Setup checks displayed", "!document.getElementById('view-check').hidden")
            window.evaluate_js("""
                document.querySelector('[data-view=vpn]').click();
                document.getElementById('vpn-role').value='responder';
                document.getElementById('vpn-role').dispatchEvent(new Event('change'));
            """)
            check(
                "VPN responder defaults",
                """
                document.getElementById('vpn-address').value==='10.77.0.2/30' &&
                document.getElementById('vpn-kill').value==='off' &&
                document.getElementById('vpn-routing').querySelector('[value=default]').disabled
            """,
            )
            worker = subprocess.run(
                desktop._worker_command(),
                input=json.dumps(
                    {"argv": ["message", "--config", str(desktop.root / "missing.toml"), "smoke"]}
                )
                + "\n",
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=10,
            )
            assert worker.returncode == 1 and '"finished"' in worker.stdout
            results["checks"].append("Bundled worker IPC and errors (no networking)")
            results["passed"] = True
        except Exception as exc:
            results["error"] = str(exc)
        finally:
            result_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
            window.destroy()

    webview.start(verify, gui="edgechromium" if sys.platform == "win32" else None)
    return 0 if results["passed"] else 1
