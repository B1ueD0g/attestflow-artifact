"""Add exact-event clock brackets outside the unchanged relay directory format.

These are same-process local wall/monotonic observations, not trusted time or
precise application receipt timestamps. Clock qualification must be conjoined
with whole-session relay qualification and the external stable-clock/origin
assumptions. No token, case, expected result, or current validation time is used.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from typing import Mapping

from .tcp_relay import CaptureError, CaptureRelay


MAX_CLOCK_BYTES = 64 << 20
MAX_EVENTS = 100_000
CLOCK_FIELDS = {"seq", "event_sha256", "event_monotonic_ns", "wall_before_ns", "wall_after_ns"}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _integer(value):
    return type(value) is int and value >= 0


class TimedCaptureRelay(CaptureRelay):
    """CaptureRelay-compatible TCP relay with a required external clock file.

    A clock error stops subsequent event recording/forwarding. Bytes already
    submitted before a later clock error cannot be undone; preserve incomplete
    evidence instead. close() finalizes the clock before base RESULT publication.
    """

    def __init__(self, output_dir, *, clock_path: Path, **options):
        super().__init__(output_dir, **options)
        if not isinstance(clock_path, Path):
            raise TypeError("clock_path must be pathlib.Path")
        self.clock_path = clock_path.absolute()
        if self.clock_path.resolve().is_relative_to(self.output_dir.resolve()):
            raise ValueError("clock_path must be outside the relay directory")
        self._clock_stream = None
        self._clock_failed = False
        self._clock_start_attempted = False
        self._clock_seq = 0
        self._clock_bytes = 0
        self._previous_mono = -1
        self._previous_wall_after = -1

    def _clock_error(self, message, exc=None):
        if not self._clock_failed:
            self.errors.append({"type": "ClockCaptureError", "message": message})
        self._clock_failed = True
        failure = CaptureError(message)
        if exc is not None:
            failure.__cause__ = exc
        return failure

    async def start(self):
        if self._clock_start_attempted or self.closed:
            raise RuntimeError("timed relay instances cannot be reused")
        self._clock_start_attempted = True
        try:
            fd = os.open(self.clock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self._clock_stream = os.fdopen(fd, "wb")
            return await super().start()
        except BaseException:
            await self.close()
            raise

    def _write_clock(self, raw):
        """Separated for local deterministic short-write/flush failure tests."""
        if self._clock_stream.write(raw) != len(raw):
            raise OSError("short event clock write")
        self._clock_stream.flush()
        os.fsync(self._clock_stream.fileno())

    def _event(self, stream, kind, **fields):
        if self._clock_failed or self._clock_stream is None or self._clock_stream.closed:
            raise self._clock_error("event clock is unavailable")
        try:
            if "event" in fields or "monotonic_ns" in fields:
                raise ValueError("reserved base-event fields")
            before = time.time_ns()
            mono = time.monotonic_ns()
            after = time.time_ns()
            if not all(_integer(x) for x in (before, mono, after)):
                raise ValueError("clock samples must be nonnegative strict integers")
            if not self._previous_wall_after <= before <= after or mono < self._previous_mono:
                raise ValueError("observed local clock moved backwards")
            if self._clock_seq >= MAX_EVENTS:
                raise ValueError("event clock count budget exceeded")
            raw = (json.dumps({"event": kind, "monotonic_ns": mono, **fields}, sort_keys=True) + "\n").encode("utf-8")
            clock = (json.dumps({"seq": self._clock_seq + 1, "event_sha256": _sha(raw),
                "event_monotonic_ns": mono, "wall_before_ns": before, "wall_after_ns": after}, sort_keys=True) + "\n").encode()
            if self._clock_bytes + len(clock) > MAX_CLOCK_BYTES:
                raise ValueError("event clock byte budget exceeded")
            # Same base-event schema/encoding as CaptureRelay. A failed sidecar
            # cannot retroactively erase this line; validators reject the gap.
            if stream.write(raw) != len(raw):
                raise OSError("short base event write")
            stream.flush()
            self._write_clock(clock)
            self._clock_seq += 1
            self._clock_bytes += len(clock)
            self._previous_mono, self._previous_wall_after = mono, after
        except Exception as exc:
            raise self._clock_error("event clock/base recording failed", exc) from exc

    async def close(self):
        if self.closed:
            return self.summary
        # Quiesce registered connection tasks before closing their shared clock.
        # Base close is still responsible for server wait/final RESULT schema.
        self.closing = True
        if self.server:
            self.server.close()
        if any(not task.done() for task in self.tasks):
            self.errors.append({"type": "ShutdownWithActiveConnections",
                "message": "timed relay shutdown interrupted unfinished capture"})
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            import asyncio
            await asyncio.gather(*tasks, return_exceptions=True)
        stream = self._clock_stream
        if stream is not None and not stream.closed:
            try:
                stream.flush()
                os.fsync(stream.fileno())
            except Exception as exc:
                self._clock_error("event clock final flush/fsync failed", exc)
            finally:
                try:
                    stream.close()
                except Exception as exc:
                    self._clock_error("event clock close failed", exc)
        return await super().close()


@dataclass(frozen=True)
class ClockEvent:
    connection_id: str
    event_index: int  # one-based position in that connection's original events
    event: dict
    event_raw: bytes  # exact original JSON line, including LF
    seq: int
    event_sha256: str
    event_monotonic_ns: int
    wall_before_ns: int
    wall_after_ns: int


@dataclass(frozen=True)
class ClockEvidence:
    qualified: bool
    reasons: tuple[str, ...]
    records_by_connection: dict[str, tuple[ClockEvent, ...]]
    clock_sha256: str | None
    boundary: str = "exact local event brackets only; whole relay qualification and stable-clock/origin assumptions external"


def _json(raw):
    def pairs(items):
        value = {}
        for k, v in items:
            if k in value:
                raise ValueError("duplicate JSON member")
            value[k] = v
        return value
    def constant(_):
        raise ValueError("non-finite JSON number")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def _lines(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_CLOCK_BYTES or not raw.endswith(b"\n"):
        raise ValueError("missing, oversized or incomplete JSONL stream")
    lines = [line + b"\n" for line in raw.split(b"\n")[:-1]]
    if len(lines) > MAX_EVENTS or any(line == b"\n" or line.endswith(b"\r\n") for line in lines):
        raise ValueError("unsupported JSONL framing/count")
    return lines


def validate_event_clock(clock_path: Path, *, event_streams: Mapping[str, bytes],
                         stable_local_clocks: bool) -> ClockEvidence:
    """Read-only exact 1:1 qualification against ALL original event streams.

    The caller must supply every connection's untouched events.jsonl and also
    qualify the complete base relay session. Missing/extra/duplicate lines,
    malformed values and absent stable-clock admission are not safe outcomes.
    Raw event hashes include LF; no wall time is estimated from iat or a clock
    read during validation. A failed check returns no qualified partial mapping.
    """
    digest = None
    try:
        if stable_local_clocks is not True:
            raise ValueError("stable local clocks must be explicitly admitted")
        if not isinstance(clock_path, Path) or not isinstance(event_streams, Mapping) or not event_streams:
            raise ValueError("clock Path and all nonempty event streams required")
        info = clock_path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CLOCK_BYTES:
            raise ValueError("clock must be a bounded non-symlink regular file")
        raw = clock_path.read_bytes()
        if len(raw) != info.st_size:
            raise ValueError("clock file changed size while reading")
        digest = _sha(raw)
        expected, counts, total_event_bytes = {}, {}, 0
        for cid, data in event_streams.items():
            if type(cid) is not str or not cid:
                raise ValueError("nonempty string connection identifiers required")
            if type(data) is not bytes:
                raise ValueError("raw original event streams must be bytes")
            total_event_bytes += len(data)
            if total_event_bytes > MAX_CLOCK_BYTES:
                raise ValueError("total original event byte budget exceeded")
            lines = _lines(data)
            counts[cid] = len(lines)
            for index, line in enumerate(lines, 1):
                event = _json(line)
                if type(event) is not dict or type(event.get("event")) is not str or not _integer(event.get("monotonic_ns")):
                    raise ValueError("invalid original event record")
                h = _sha(line)
                if h in expected:
                    raise ValueError("duplicate original event hash; association is ambiguous")
                expected[h] = (cid, index, line, event)
                if len(expected) > MAX_EVENTS:
                    raise ValueError("total event count budget exceeded")
        records = _lines(raw)
        if len(records) != len(expected):
            raise ValueError("clock/event count mismatch (missing or extra records)")
        seen, positions, grouped = set(), {cid: 0 for cid in counts}, {cid: [] for cid in counts}
        previous_wall, previous_mono = -1, -1
        for seq, line in enumerate(records, 1):
            clock = _json(line)
            if type(clock) is not dict or set(clock) != CLOCK_FIELDS:
                raise ValueError("unknown/missing clock fields")
            if not all(_integer(clock[k]) for k in CLOCK_FIELDS - {"event_sha256"}):
                raise ValueError("clock counters/timestamps must be strict nonnegative integers")
            h = clock["event_sha256"]
            if type(h) is not str or h not in expected or h in seen or clock["seq"] != seq:
                raise ValueError("clock hash/sequence mismatch or duplicate")
            cid, index, original, event = expected[h]
            mono, before, after = (clock[k] for k in ("event_monotonic_ns", "wall_before_ns", "wall_after_ns"))
            if mono != event["monotonic_ns"] or mono < previous_mono or not previous_wall <= before <= after:
                raise ValueError("clock/event time mismatch or backwards time")
            if index != positions[cid] + 1:
                raise ValueError("clock order disagrees with original connection event order")
            positions[cid] = index
            seen.add(h)
            grouped[cid].append(ClockEvent(cid, index, event, original, seq, h, mono, before, after))
            previous_mono, previous_wall = mono, after
        if positions != counts or seen != set(expected):
            raise ValueError("not every original event is clock-bound")
        return ClockEvidence(True, (), {cid: tuple(items) for cid, items in grouped.items()}, digest)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        return ClockEvidence(False, (f"{type(exc).__name__}: {exc}",), {}, digest)


def captured_wall_span(evidence: ClockEvidence, *, connection_id: str,
                       direction: str, start: int, end: int) -> tuple[int, int]:
    """Conservative wall bracket enclosing CAPTURED events covering byte range.

    This brackets recorder event sampling, NOT original read/application receipt.
    To bound a server decision, combine request capture with later response
    capture according to the externally justified ordering/forwarding contract.
    """
    if not isinstance(evidence, ClockEvidence) or evidence.qualified is not True:
        raise ValueError("qualified complete event clock required")
    if type(connection_id) is not str or not connection_id or direction not in ("client_to_upstream", "upstream_to_client") or not _integer(start) or not _integer(end) or start >= end:
        raise ValueError("valid direction and nonempty strict integer byte span required")
    selected = []
    for item in evidence.records_by_connection.get(connection_id, ()):
        event = item.event
        if event["event"] == "CAPTURED" and event.get("direction") == direction:
            offset, size = event.get("offset"), event.get("size")
            if not _integer(offset) or not _integer(size) or size == 0:
                raise ValueError("invalid CAPTURED byte interval")
            if offset < end and offset + size > start:
                selected.append(item)
    if not selected or selected[0].event["offset"] > start or selected[-1].event["offset"] + selected[-1].event["size"] < end:
        raise ValueError("capture events do not cover requested byte span")
    for left, right in zip(selected, selected[1:]):
        if left.event["offset"] + left.event["size"] != right.event["offset"]:
            raise ValueError("noncontiguous or overlapping CAPTURED intervals")
    return selected[0].wall_before_ns, selected[-1].wall_after_ns
