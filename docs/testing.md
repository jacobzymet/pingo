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
