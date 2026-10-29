"""Private desktop subprocess. Only structured CLI arguments arrive on stdin."""

import json
import sys
import threading

from .cli import main


def run():
    stop = threading.Event()
    lock = threading.Lock()

    def emit(kind, **fields):
        with lock:
            print(json.dumps({"event": kind, **fields}), flush=True)

    try:
        request = json.loads(sys.stdin.readline())
        argv = request["argv"]
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            raise ValueError("invalid desktop request")
        if not argv or argv[0] not in ("listen", "message", "file", "vpn", "unlock", "probe"):
            raise ValueError("unsupported desktop operation")

        def watch_parent():
            # EOF also stops networking if the desktop disappears unexpectedly.
            for line in sys.stdin:
                if line.strip() == "stop":
                    break
            stop.set()

        threading.Thread(target=watch_parent, daemon=True).start()
        code = main(argv, events=emit, stop=stop)
    except (KeyError, TypeError, ValueError, OSError) as exc:
        emit("error", text=str(exc))
        code = 1
    emit("finished", code=code)
    return code


if __name__ == "__main__":
    raise SystemExit(run())
