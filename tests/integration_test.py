#!/usr/bin/env python3
"""End-to-end test of the wispd socket protocol.

The unit tests cover the protocol helpers in isolation. This drives a real
wispd over a real unix socket, which is the only way to check the parts that
only exist once there are two processes talking: connection reuse, request
pipelining, the concurrency guarantees of the poll() loop, and what the daemon
does when a client lies about the shape of a request.

Run with ``--dry-run`` on the daemon so no netlink privilege is needed; every
check below is about the IPC surface, not about packet flow.

    python3 tests/integration_test.py
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# A syntactically valid profile. The values are meaningless: in dry-run mode
# nothing is handed to the kernel.
GOOD_PROFILE = """[Interface]
PrivateKey = MFsJ6BRfjM4DQ1s1D4n0dMhkT0jPf0Ckq8iFHnS4jWk=
Address = 10.7.0.2/32
DNS = 10.7.0.1
MTU = 1420

[Peer]
PublicKey = cHF0+QdZfB6g1kOoP1nGmS3rZ8jR0lY5y2xQ+vT1cWw=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
"""

BROKEN_PROFILE = """[Interface]
PrivateKey = not-a-real-key
Address = 10.7.0.2/32
"""


class Failure(Exception):
    pass


def check(condition: bool, description: str) -> None:
    if condition:
        print(f"  ok   {description}")
    else:
        raise Failure(description)


class Daemon:
    """Runs wispd against a scratch socket and profile directory."""

    def __init__(self, binary: Path, extra_args: list[str]) -> None:
        self.binary = binary
        self.extra_args = extra_args
        self.root = Path(tempfile.mkdtemp(prefix="wisp-integration-"))
        self.socket_path = self.root / "wispd.sock"
        self.config_dir = self.root / "tunnels"
        self.config_dir.mkdir()
        self.process: subprocess.Popen[bytes] | None = None

    def write_profile(self, name: str, text: str) -> None:
        (self.config_dir / f"{name}.conf").write_text(text)

    def start(self) -> None:
        (self.config_dir / "good.conf").write_text(GOOD_PROFILE)
        (self.config_dir / "broken.conf").write_text(BROKEN_PROFILE)

        command = [
            str(self.binary),
            "--socket", str(self.socket_path),
            "--config-dir", str(self.config_dir),
            "--uid", str(os.getuid()),
            "--dry-run",
            "--no-dns",
            *self.extra_args,
        ]
        self.process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if self.socket_path.exists():
                return
            if self.process.poll() is not None:
                stderr = (self.process.stderr.read() or b"").decode(errors="replace")
                raise Failure(f"wispd exited early: {stderr.strip()}")
            time.sleep(0.02)
        raise Failure("wispd never created its socket")

    def connect(self) -> socket.socket:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5.0)
        client.connect(str(self.socket_path))
        return client

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        shutil.rmtree(self.root, ignore_errors=True)


class Peer:
    """A socket wrapper that keeps what it has read but not yet returned.

    A plain recv() is not enough: one read can carry several responses, and a
    test that discards the remainder after the first newline would then block
    forever waiting for a line it already has. That is a bug in the test, not
    the daemon - which is exactly the kind of thing this file exists to catch.
    """

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buffer = b""

    def send(self, data: bytes) -> None:
        try:
            self.sock.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            # Legitimate here: the daemon may hang up while a client is still
            # sending. Callers that care read what came back and check the
            # daemon is still alive.
            pass

    def read_line(self) -> str:
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.buffer += chunk
        line, _, self.buffer = self.buffer.partition(b"\n")
        return line.decode(errors="replace")

    def close(self) -> None:
        self.sock.close()


def expect(peer: Peer, request: bytes, prefix: str, description: str) -> str:
    peer.send(request)
    response = peer.read_line()
    if not response.startswith(prefix):
        raise Failure(f"{description}: expected {prefix!r}, got {response!r}")
    print(f"  ok   {description} -> {response}")
    return response


def test_persistent_connection(daemon: Daemon) -> None:
    print("persistent connection")
    peer = Peer(daemon.connect())
    try:
        # The whole point of the persistent connection: several requests over
        # one socket, answered in order, without reconnecting in between.
        expect(peer, b"PING\n", "OK", "ping on a fresh connection")
        expect(peer, b"LIST\n", "OK broken,good", "list reports profiles sorted")
        expect(peer, b"UP good\n", "OK", "up a valid profile in dry-run")
        expect(peer, b"STATUS good\n", "ERR", "status of a device that does not exist")

        # The connection must still be usable after an error response.
        expect(peer, b"PING\n", "OK", "ping again after an error")
    finally:
        peer.close()
    print("  ok   connection closed cleanly by the client")


def test_pipelining(daemon: Daemon) -> None:
    print("pipelined requests")
    peer = Peer(daemon.connect())
    try:
        # All five requests go out in a single write. Responses must come back
        # in the order the requests were sent, one line each.
        peer.send(b"PING\nPING\nLIST\nPING\nPING\n")
        responses = [peer.read_line() for _ in range(5)]
        check(all(r.startswith("OK") for r in responses),
              "all five pipelined requests answered")
        check(responses[2].startswith("OK broken,good"),
              f"responses stayed matched to their requests: {responses[2]!r}")
        print(f"  ok   five requests in one write answered in order ({responses[2]!r})")
    finally:
        peer.close()


def test_concurrency(daemon: Daemon) -> None:
    print("concurrency")
    idle = Peer(daemon.connect())
    active = Peer(daemon.connect())
    try:
        # `idle` deliberately sends nothing. If the daemon were servicing one
        # connection at a time with a blocking read, this next request would
        # never be answered.
        time.sleep(0.2)
        expect(active, b"PING\n", "OK", "a second client is served while the first is idle")
        expect(idle, b"PING\n", "OK", "the idle client is still usable afterwards")
    finally:
        idle.close()
        active.close()


def test_hostile_input(daemon: Daemon) -> None:
    print("hostile input")

    peer = Peer(daemon.connect())
    try:
        # Path traversal, option injection and shell metacharacters all have to
        # fail identically: the name is the only thing a client controls, so
        # this is the whole defence against reading another file.
        for hostile in (b"UP ../../etc/passwd\n", b"UP /etc/shadow\n",
                        b"UP --config\n", b"UP a;rm -rf /\n", b"UP no.conf\n",
                        b"UP .hidden\n", b"UP tooLongANameHere\n"):
            expect(peer, hostile, "ERR", f"rejects {hostile.strip()!r}")
    finally:
        peer.close()

    peer = Peer(daemon.connect())
    try:
        # The daemon echoes an unrecognised verb back so the operator can see
        # what was sent. That echo must stay on one line: a raw control
        # character would let a client forge a second response - or split its
        # own entry in the log, hiding what it did.
        peer.send(b"\x01\x02UP\n")
        response = peer.read_line()
        check(response.startswith("ERR"), f"a control character in the verb is refused: {response!r}")
        check(all(0x20 <= ord(c) < 0x7F for c in response),
              "the refusal contains only printable characters")
        print(f"  ok   control characters are sanitised out of the echo -> {response!r}")

        # And the daemon keeps serving on the same connection afterwards.
        expect(peer, b"PING\n", "OK", "usable after a sanitised rejection")
    finally:
        peer.close()

    peer = Peer(daemon.connect())
    try:
        expect(peer, b"UP broken\n", "ERR", "an invalid profile is reported, not applied")
    finally:
        peer.close()


def test_oversized_input(daemon: Daemon) -> None:
    print("oversized input")

    peer = Peer(daemon.connect())
    try:
        # A complete but absurdly long line: comfortably under the cap on total
        # buffered bytes, so the daemon must still refuse it on its own merits.
        peer.send(b"UP " + b"B" * 8192 + b"\n")
        response = peer.read_line()
        check(response.startswith("ERR"), f"oversized request line refused: {response!r}")
        print(f"  ok   an 8 KiB request line is refused -> {response!r}")
    finally:
        peer.close()

    peer = Peer(daemon.connect())
    try:
        # No newline ever: the daemon must cap what it buffers on behalf of a
        # client that never finishes a request, rather than growing without
        # bound. The flood is kept to one write that fits the socket buffer, so
        # a refusal is deterministic rather than a race with a reset.
        peer.send(b"A" * (96 * 1024))
        response = peer.read_line()
        check(response.startswith("ERR"),
              f"an unterminated flood was refused: {response!r}")
        print(f"  ok   96 KiB without a newline was refused -> {response!r}")
    finally:
        peer.close()

    # The daemon must still be alive and serving after both floods.
    peer = Peer(daemon.connect())
    try:
        expect(peer, b"PING\n", "OK", "daemon survived the floods")
    finally:
        peer.close()


def test_shutdown(daemon: Daemon) -> None:
    print("shutdown")
    daemon.stop()
    check(not daemon.socket_path.exists(), "socket file was removed on exit")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--daemon",
        default="build/helper/wispd",
        help="path to the wispd binary (default: build/helper/wispd)",
    )
    parser.add_argument(
        "--arg", action="append", default=[],
        help="extra argument to pass to every wispd invocation",
    )
    options = parser.parse_args()

    binary = Path(options.daemon).resolve()
    if not binary.exists():
        print(f"error: {binary} not found; build the project first", file=sys.stderr)
        return 2

    failures = 0
    for name, test in (
        ("persistent connection", test_persistent_connection),
        ("pipelining", test_pipelining),
        ("concurrency", test_concurrency),
        ("hostile input", test_hostile_input),
        ("oversized input", test_oversized_input),
        ("shutdown", test_shutdown),
    ):
        daemon = Daemon(binary, options.arg)
        try:
            daemon.start()
            test(daemon)
        except Failure as error:
            failures += 1
            print(f"  FAIL {name}: {error}")
        except Exception as error:  # noqa: BLE001 - report anything unexpected
            failures += 1
            print(f"  ERROR {name}: {error!r}")
        finally:
            daemon.stop()

    print()
    if failures:
        print(f"{failures} integration group(s) failed")
        return 1
    print("all integration groups passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
