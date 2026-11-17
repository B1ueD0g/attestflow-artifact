"""Byte-transparent loopback TCP measurement relay for local dummy fixtures.

Raw files contain bytes *read* from each peer, not evidence of peer application
receipt. Successful drain only means submission to the local transport. This
module deliberately does not parse HTTP, JWTs, authorization, or application
effects. See README.md for capture validity and perturbation boundaries.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import signal
import socket
import stat
import sys
import tempfile
import time
from typing import BinaryIO


DIRECTIONS = ("client_to_upstream", "upstream_to_client")


class CaptureError(RuntimeError):
    """Recording did not complete; uncaptured bytes must not be forwarded."""


class IdleTimeout(TimeoutError):
    """The whole connection, not just one direction, was idle too long."""


class ConnectTimeout(TimeoutError):
    """The configured upstream connection could not be established in time."""


def _loopback(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_loopback:
        raise ValueError("Only literal IPv4 loopback addresses are allowed")
    return str(address)


def _exclusive_binary(path: Path) -> BinaryIO:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")


def _publish_json(path: Path, value: dict) -> None:
    """Publish a complete, flushed JSON file without overwriting any target.

    A write failure retains .partial bytes; a final name exists only after a
    complete write/fsync. This is not a power-loss or hostile-filesystem proof.
    """
    partial = path.with_name(path.name + ".partial")
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    with _exclusive_binary(partial) as stream:
        if stream.write(data) != len(data):
            raise OSError("short JSON write")
        stream.flush()
        os.fsync(stream.fileno())
    os.link(partial, path)  # exclusive final name, unlike overwrite-capable rename
    partial.unlink()  # this function's own retained temporary link, after publish


def _error(exc: BaseException) -> dict:
    return {"type": type(exc).__name__, "message": str(exc)}


def _peer(writer):
    value = writer.get_extra_info("peername")
    return list(value) if isinstance(value, tuple) else value


class CaptureRelay:
    def __init__(
        self,
        output_dir: str | Path,
        *,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8081,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 8082,
        idle_timeout: float = 30.0,
        connect_timeout: float = 5.0,
        max_bytes_per_direction: int = 16 * 1024 * 1024,
    ):
        self.listen_host = _loopback(listen_host)
        self.upstream_host = _loopback(upstream_host)
        if not 0 <= listen_port <= 65535 or not 1 <= upstream_port <= 65535:
            raise ValueError("invalid TCP port; only listen may use ephemeral port 0")
        if (not math.isfinite(idle_timeout) or not math.isfinite(connect_timeout)
                or idle_timeout <= 0 or connect_timeout <= 0 or max_bytes_per_direction <= 0):
            raise ValueError("timeouts and capture size limit must be positive")
        if listen_port and (self.listen_host, listen_port) == (self.upstream_host, upstream_port):
            raise ValueError("relay cannot target its own listening endpoint")
        self.listen_port = listen_port
        self.upstream_port = upstream_port
        self.output_dir = Path(output_dir)
        self.idle_timeout = float(idle_timeout)
        self.connect_timeout = float(connect_timeout)
        self.max_bytes_per_direction = max_bytes_per_direction
        self.server: asyncio.AbstractServer | None = None
        self.connections: list[dict] = []
        self.errors: list[dict] = []
        self.tasks: set[asyncio.Task] = set()
        self.closing = False
        self.started = False
        self.closed = False
        self.summary: dict | None = None
        self.transport = "tcp"

    def _endpoints(self) -> dict:
        return {"transport": self.transport,
                "listen": [self.listen_host, self.listen_port],
                "upstream": [self.upstream_host, self.upstream_port]}

    async def _listen(self):
        return await asyncio.start_server(
            self._accept, self.listen_host, self.listen_port, family=socket.AF_INET,
        )

    async def _connect(self):
        return await asyncio.open_connection(
            self.upstream_host, self.upstream_port, family=socket.AF_INET,
        )

    async def start(self) -> "CaptureRelay":
        if self.started or self.closed:
            raise RuntimeError("relay instances cannot be reused")
        # Existing output is never reused, merged, truncated, or removed.
        self.output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.started = True
        try:
            _publish_json(self.output_dir / "SESSION.json", {
                "schema": "attestflow-loopback-relay-v1",
                "state": "STARTED_NOT_COMPLETE",
                "started_unix_ns": time.time_ns(),
                **self._endpoints(),
                "idle_timeout_seconds": self.idle_timeout,
                "connect_timeout_seconds": self.connect_timeout,
                "max_bytes_per_direction": self.max_bytes_per_direction,
                "boundary": "inline dummy TCP observation; no application verdict",
            })
            self.server = await self._listen()
            if self.transport == "tcp":
                self.listen_port = self.server.sockets[0].getsockname()[1]
                if (self.listen_host, self.listen_port) == (self.upstream_host, self.upstream_port):
                    raise ValueError("ephemeral listener collided with upstream endpoint")
            _publish_json(self.output_dir / "READY.json", self._endpoints())
        except BaseException as exc:
            self.errors.append(_error(exc))
            await self.close()
            raise
        return self

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(self._connection(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    @staticmethod
    def _event(stream: BinaryIO, kind: str, **fields) -> None:
        data = (json.dumps({"event": kind, "monotonic_ns": time.monotonic_ns(),
                            **fields}, sort_keys=True) + "\n").encode("utf-8")
        try:
            if stream.write(data) != len(data):
                raise OSError("short event write")
            stream.flush()
        except Exception as exc:
            raise CaptureError("event capture failed") from exc

    def _capture_chunk(self, stream: BinaryIO, data: bytes) -> None:
        # A separate method permits deterministic disk-failure development tests.
        try:
            if stream.write(data) != len(data):
                raise OSError("short raw capture write")
            stream.flush()
        except Exception as exc:
            raise CaptureError("raw byte capture failed") from exc

    async def _connection(self, client_reader, client_writer) -> None:
        number = len(self.connections) + 1
        state = {
            "connection_id": f"connection-{number:06d}",
            "capture_complete": False,
            "started_unix_ns": time.time_ns(),
            "client_peer": _peer(client_writer),
            "directions": {d: {"read_bytes": 0, "submitted_bytes": 0,
                               "eof_observed": False, "write_eof_submitted": False}
                           for d in DIRECTIONS},
            "errors": [],
        }
        self.connections.append(state)
        directory = self.output_dir / state["connection_id"]
        streams: dict[str, BinaryIO] = {}
        event_stream = None
        upstream_writer = None
        children: list[asyncio.Task] = []
        last_activity = time.monotonic()
        transport_complete = False

        async def pump(reader, writer, direction):
            nonlocal last_activity
            stats = state["directions"][direction]
            while True:
                data = await reader.read(65536)
                if not data:
                    stats["eof_observed"] = True
                    self._event(event_stream, "READ_EOF", direction=direction)
                    if not writer.can_write_eof():
                        raise RuntimeError("TCP transport cannot preserve half-close")
                    writer.write_eof()
                    await writer.drain()
                    stats["write_eof_submitted"] = True
                    self._event(event_stream, "WRITE_EOF_SUBMITTED", direction=direction)
                    return
                last_activity = time.monotonic()
                offset = stats["read_bytes"]
                stats["read_bytes"] += len(data)
                if stats["read_bytes"] > self.max_bytes_per_direction:
                    raise CaptureError("per-direction capture byte limit exceeded")
                self._capture_chunk(streams[direction], data)
                self._event(event_stream, "CAPTURED", direction=direction,
                            offset=offset, size=len(data), sha256=hashlib.sha256(data).hexdigest())
                writer.write(data)
                await writer.drain()
                stats["submitted_bytes"] += len(data)
                self._event(event_stream, "WRITE_SUBMITTED", direction=direction,
                            offset=offset, size=len(data))

        async def watchdog():
            while True:
                remaining = self.idle_timeout - (time.monotonic() - last_activity)
                if remaining <= 0:
                    raise IdleTimeout("connection idle timeout; capture is incomplete")
                await asyncio.sleep(remaining)

        try:
            directory.mkdir(mode=0o700, exist_ok=False)
            _publish_json(directory / "START.json", {
                "connection_id": state["connection_id"],
                "started_unix_ns": state["started_unix_ns"],
                "client_peer": state["client_peer"],
            })
            event_stream = _exclusive_binary(directory / "events.jsonl")
            for direction in DIRECTIONS:
                streams[direction] = _exclusive_binary(directory / (direction + ".bin"))
            self._event(event_stream, "ACCEPTED")
            if self.closing:
                raise RuntimeError("relay shutdown before upstream connection")
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    self._connect(), self.connect_timeout,
                )
            except TimeoutError as exc:
                raise ConnectTimeout("upstream connection timeout; no complete capture") from exc
            state["upstream_peer"] = _peer(upstream_writer)
            self._event(event_stream, "UPSTREAM_CONNECTED", peer=state["upstream_peer"])
            pending = {
                asyncio.create_task(pump(client_reader, upstream_writer, DIRECTIONS[0])),
                asyncio.create_task(pump(upstream_reader, client_writer, DIRECTIONS[1])),
            }
            timer = asyncio.create_task(watchdog())
            children = list(pending) + [timer]
            while pending:
                done, _ = await asyncio.wait(pending | {timer}, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()  # propagate errors; neither EOF alone means complete
                    pending.discard(task)
            transport_complete = True
            self._event(event_stream, "BIDIRECTIONAL_EOF_OBSERVED")
        except BaseException as exc:
            state["errors"].append(_error(exc))
            if event_stream:
                try:
                    self._event(event_stream, "INCOMPLETE", error=_error(exc))
                except BaseException as logging_exc:
                    state["errors"].append(_error(logging_exc))
            print(f"relay {state['connection_id']} incomplete: {type(exc).__name__}",
                  file=sys.stderr, flush=True)
        finally:
            for task in children:
                if not task.done():
                    task.cancel()
            if children:
                await asyncio.gather(*children, return_exceptions=True)
            for writer in (upstream_writer, client_writer):
                if writer:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), self.connect_timeout)
                    except BaseException as exc:
                        state["errors"].append(_error(exc))
            for stream in list(streams.values()) + ([event_stream] if event_stream else []):
                try:
                    stream.flush()
                    os.fsync(stream.fileno())
                    stream.close()
                except BaseException as exc:
                    state["errors"].append(_error(exc))
                    try:
                        stream.close()
                    except BaseException:
                        pass
            for direction in DIRECTIONS:
                try:
                    raw = directory / (direction + ".bin")
                    digest = hashlib.sha256()
                    size = 0
                    with raw.open("rb") as stream:
                        while chunk := stream.read(65536):
                            digest.update(chunk)
                            size += len(chunk)
                    state["directions"][direction]["captured_file_bytes"] = size
                    state["directions"][direction]["captured_file_sha256"] = digest.hexdigest()
                    if size != state["directions"][direction]["read_bytes"]:
                        state["errors"].append({"type": "CaptureLengthMismatch",
                                                "message": direction})
                except BaseException as exc:
                    state["errors"].append(_error(exc))
            state["ended_unix_ns"] = time.time_ns()
            state["capture_complete"] = bool(transport_complete and not state["errors"])
            try:
                _publish_json(directory / "END.json", state)
            except BaseException as exc:
                state["capture_complete"] = False
                state["errors"].append(_error(exc))
                print(f"relay {state['connection_id']} final capture publish failed",
                      file=sys.stderr, flush=True)

    async def close(self) -> dict:
        if self.closed:
            return self.summary
        self.closing = True
        if self.server:
            self.server.close()
        # Closing with active sockets is explicitly incomplete, not a graceful EOF.
        if any(not task.done() for task in self.tasks):
            self.errors.append({"type": "ShutdownWithActiveConnections",
                                "message": "shutdown interrupted unfinished transport capture"})
        for task in list(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)
        if self.server:
            # Python 3.12+ wait_closed may wait for active client transports, so
            # only await it AFTER canceling/closing the captured connections.
            try:
                await asyncio.wait_for(self.server.wait_closed(), self.connect_timeout)
            except BaseException as exc:
                self.errors.append(_error(exc))
        self.summary = {
            "schema": "attestflow-loopback-relay-result-v1",
            "capture_complete": not self.errors and all(c["capture_complete"] for c in self.connections),
            "connection_count": len(self.connections),
            "connections": self.connections,
            "errors": self.errors,
            "ended_unix_ns": time.time_ns(),
            "boundary": "transport capture only; no token binding or application verdict",
        }
        if not self.connections:
            self.summary["capture_complete"] = False
            self.summary["errors"].append({"type": "NoConnections", "message": "no observed application traffic"})
        if self.started:
            try:
                _publish_json(self.output_dir / "RESULT.json", self.summary)
            except BaseException as exc:
                self.summary["capture_complete"] = False
                self.summary["errors"].append(_error(exc))
                print("relay RESULT publish failed; retained files are incomplete", file=sys.stderr, flush=True)
        self.closed = True
        return self.summary


class UnixCaptureRelay(CaptureRelay):
    """Private temporary CDH RPC socket relay; never the AA GetToken socket."""

    def __init__(self, output_dir, *, private_socket_dir, listen_socket="front.sock",
                 upstream_socket="back.sock", **options):
        super().__init__(output_dir, **options)
        private = Path(private_socket_dir)
        if not private.is_absolute() or private.is_symlink():
            raise ValueError("private socket directory must be absolute and not a symlink")
        private_stat = private.stat()
        if (not stat.S_ISDIR(private_stat.st_mode) or private_stat.st_uid != os.getuid()
                or stat.S_IMODE(private_stat.st_mode) != 0o700):
            raise ValueError("private socket directory must be current-UID-owned mode 0700")
        private = private.resolve(strict=True)
        temporary = Path(tempfile.gettempdir()).resolve(strict=True)
        if not private.is_relative_to(temporary) or not private.name.startswith("attestflow-"):
            raise ValueError("private socket directory must be an attestflow-* directory below system tmp")
        for name in (listen_socket, upstream_socket):
            if not isinstance(name, str) or not name or Path(name).name != name or name in (".", ".."):
                raise ValueError("socket names must be simple direct-child filenames")
            if "attestation-agent" in name.lower():
                raise ValueError("AA socket capture is outside this relay's scope")
        if listen_socket == upstream_socket:
            raise ValueError("front and back sockets must differ")
        self.private_socket_dir = private
        self.listen_socket = private / listen_socket
        self.upstream_socket = private / upstream_socket
        self.transport = "unix_cdh_rpc"

    def _endpoints(self) -> dict:
        return {"transport": self.transport, "listen": str(self.listen_socket),
                "upstream": str(self.upstream_socket),
                "private_socket_dir": str(self.private_socket_dir),
                "scope": "dummy CDH RPC only; never AA GetToken"}

    async def _listen(self):
        # bind() on a new AF_UNIX socket does NOT unlink a preexisting socket.
        # Avoid start_unix_server(path=...), which may remove an existing socket.
        if os.path.lexists(self.listen_socket):
            raise FileExistsError(f"existing frontend path is protected: {self.listen_socket}")
        if self.upstream_socket.is_symlink():
            raise ValueError("upstream socket cannot be a symlink")
        if not stat.S_ISSOCK(self.upstream_socket.stat().st_mode):
            raise ValueError("upstream must already be a Unix socket in the private directory")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.listen_socket))
            os.chmod(self.listen_socket, 0o600)
            listener.listen(socket.SOMAXCONN)
            listener.setblocking(False)
            return await asyncio.start_unix_server(self._accept, sock=listener)
        except BaseException:
            listener.close()
            raise

    async def _connect(self):
        return await asyncio.open_unix_connection(str(self.upstream_socket))


async def _main(args) -> int:
    options = {"idle_timeout": args.idle_timeout, "connect_timeout": args.connect_timeout,
               "max_bytes_per_direction": args.max_bytes_per_direction}
    if args.private_socket_dir:
        relay = UnixCaptureRelay(args.output, private_socket_dir=args.private_socket_dir,
                                 listen_socket=args.listen_socket,
                                 upstream_socket=args.upstream_socket, **options)
    else:
        relay = CaptureRelay(args.output, listen_host=args.listen_host, listen_port=args.listen_port,
                             upstream_host=args.upstream_host, upstream_port=args.upstream_port, **options)
    await relay.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    print(json.dumps({"state": "READY", **relay._endpoints()}), flush=True)
    await stop.wait()
    summary = await relay.close()
    print(json.dumps({"state": "CLOSED", "capture_complete": summary["capture_complete"],
                      "connection_count": summary["connection_count"]}), flush=True)
    return 0 if summary["capture_complete"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="exclusive NEW directory; parent must exist")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8081)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=8082)
    parser.add_argument("--idle-timeout", type=float, default=30.0)
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--max-bytes-per-direction", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--private-socket-dir", help="enable private temporary CDH Unix RPC relay (not AA)")
    parser.add_argument("--listen-socket", default="front.sock")
    parser.add_argument("--upstream-socket", default="back.sock")
    try:
        return asyncio.run(_main(parser.parse_args()))
    except Exception as exc:
        print(f"relay startup/execution failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
