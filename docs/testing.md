# Testing

## Unit tests

```sh
python -m pip install -e '.[dev]'
python -m pytest -q -m 'not live'
python -m ruff check src tests
python -m compileall -q src
```

Unit tests use simulated transports, mock TUN/Wintun APIs, and mock system-command
runners. They do not change host networking. Tests marked `live` run only when
explicitly enabled. CI runs unit tests on Windows and Linux with Python 3.11 and 3.13.

## Linux integration tests

Run networking tests inside an isolated container:

```sh
docker build -t pingo-live-test -f tests/live/Dockerfile .
docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --device /dev/net/tun --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined pingo-live-test
```

The image sets `PINGO_LIVE=1`. Tests create private network namespaces and veth
pairs, configure ICMP endpoints, and start separate Pingo processes. Cleanup
terminates the test processes and removes their namespaces. Do not use host
network mode or mount a writable host directory.

The integration suite covers ICMP messages and files, durable transfer resumption,
TUN delivery, route cleanup, reconnection, crash protection, and targeted unlock.

## Desktop tests

Install the `gui` extra to run desktop tests that use pywebview:

```sh
python -m pip install -e '.[dev,gui]'
python -m pytest -q tests/test_desktop.py
```

The Noise conformance test uses a published NNpsk0 known-answer vector. Session
tests also exercise handshake loss, tampering, mode/version binding, confirmation,
replay, replacement, and later PSK disclosure.

Offline measurement and experiment tests need the optional `research` extra:

```sh
python -m pip install -e '.[dev,research]'
python -m pytest -q tests/test_noise_vectors.py tests/test_measure.py
```

The Windows native smoke test opens a hidden WebView2 window and exercises the
JavaScript/Python bridge. It creates test keys and settings under the result file's
directory and does not start network actions:

```powershell
.\.venv\Scripts\python.exe -m pingo.desktop --smoke-test output/playwright/native-smoke.json
dist/Pingo/Pingo.exe --smoke-test output/playwright/packaged-smoke.json
```

`scripts/desktop-ui-check.js` exercises the interface with a simulated desktop
bridge. Serve the embedded static HTML on localhost port 8766, then run:

```sh
playwright-cli -s=pingo run-code --filename scripts/desktop-ui-check.js
```
