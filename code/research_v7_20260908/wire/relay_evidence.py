"""Read-only structural qualification of the pinned local relay capture format.

No network/process operation, protocol parsing, EAR selection or effect verdict.
`qualified` is conditional on the runner's collector identity/process/provenance
assumptions. It is not authentication against a same-root package replacement.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat


DIRECTIONS = ("client_to_upstream", "upstream_to_client")
MAX_METADATA_BYTES = 4 << 20
MAX_RAW_BYTES = 64 << 20
MAX_TOTAL_BYTES = 128 << 20
MAX_CONNECTIONS = 256
MAX_EVENTS = 100_000
CONNECTION_NAME = re.compile(r"connection-[0-9]{6}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
BOUNDARY = ("structural transport capture under externally supplied endpoints; "
            "collector/process identity, runner exit and provenance external; "
            "submitted bytes are not peer application receipt")


@dataclass(frozen=True)
class ConnectionEvidence:
    connection_id: str
    client_to_upstream: bytes | None
    upstream_to_client: bytes | None
    locally_complete: bool
    qualified: bool
    client_eof_observed: bool
    upstream_eof_observed: bool
    read_bytes: dict[str, int]
    submitted_bytes: dict[str, int]
    classifications: tuple[str, ...]
    reasons: tuple[str, ...]
    boundary: str = BOUNDARY


@dataclass(frozen=True)
class RelayEvidence:
    qualified: bool
    expected_transport: str
    expected_listen: tuple[str, int] | str
    expected_upstream: tuple[str, int] | str
    connections: tuple[ConnectionEvidence, ...]
    classifications: tuple[str, ...]
    reasons: tuple[str, ...]
    file_sha256: dict[str, str]
    boundary: str = BOUNDARY


class _Invalid(ValueError):
    pass


class _Issues:
    def __init__(self):
        self.reasons: list[str] = []
        self.classes: set[str] = set()

    def add(self, reason, category="INVALID_EVIDENCE"):
        if reason not in self.reasons:
            self.reasons.append(reason)
        self.classes.add(category)


def _require(condition, reason):
    if not condition:
        raise _Invalid(reason)


def _integer(value):
    return type(value) is int and value >= 0


def _same_json(left, right):
    """Compare parsed JSON copies without Python's bool/int/float equivalence."""
    pending = [(left, right)]
    while pending:
        one, two = pending.pop()
        if type(one) is not type(two):
            return False
        if type(one) is dict:
            if one.keys() != two.keys():
                return False
            pending.extend((one[key], two[key]) for key in one)
        elif type(one) is list:
            if len(one) != len(two):
                return False
            pending.extend(zip(one, two))
        elif one != two:
            return False
    return True


def _keys(value, required, optional=()):
    _require(type(value) is dict, "record must be a JSON object")
    _require(set(required) <= set(value) <= set(required) | set(optional),
             "missing/unknown record fields")


def _json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            _require(key not in result, "duplicate JSON member")
            result[key] = value
        return result

    def nonfinite(value):
        raise _Invalid("non-finite JSON number")

    def finite_float(value):
        parsed = float(value)
        _require(math.isfinite(parsed), "non-finite JSON number")
        return parsed

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=nonfinite, parse_float=finite_float)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise _Invalid(f"invalid JSON: {type(error).__name__}") from error


class _Reader:
    def __init__(self, root):
        self.root = root
        self.total = 0
        self.hashes = {}

    def bytes(self, path, issues, limit=MAX_METADATA_BYTES):
        name = path.relative_to(self.root).as_posix()
        try:
            info = path.lstat()
            _require(stat.S_ISREG(info.st_mode), "not a regular file (symlinks rejected)")
            _require(info.st_size <= limit, "file size budget exceeded")
            _require(self.total + info.st_size <= MAX_TOTAL_BYTES, "total read budget exceeded")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                _require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "opened non-regular file")
                raw = stream.read(limit + 1)
            _require(len(raw) == info.st_size, "file changed size while being read")
            _require(len(raw) <= limit, "file size budget exceeded")
            self.total += len(raw)
            self.hashes[name] = hashlib.sha256(raw).hexdigest()
            return raw
        except FileNotFoundError:
            issues.add(f"{name}: missing", "MISSING_RECORD")
        except (OSError, _Invalid) as error:
            issues.add(f"{name}: {error}")
        return None

    def record(self, path, issues):
        raw = self.bytes(path, issues)
        if raw is None:
            return None
        try:
            return _json(raw)
        except _Invalid as error:
            issues.add(f"{path.relative_to(self.root)}: {error}")
            return None


def _tcp_endpoint(value, allow_zero=False):
    _require(type(value) in (tuple, list) and len(value) == 2, "TCP endpoint must be host/port")
    host, port = value
    _require(type(host) is str and type(port) is int, "invalid TCP host/port type")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise _Invalid("TCP address must be literal loopback IPv4") from error
    _require(address.version == 4 and address.is_loopback and str(address) == host,
             "TCP address must be canonical loopback IPv4")
    _require((0 if allow_zero else 1) <= port <= 65535, "invalid TCP port")
    return host, port


def _unix_endpoint(value):
    _require(type(value) is str and value and "\x00" not in value and "\\" not in value,
             "Unix endpoint must be an absolute path string")
    path = PurePosixPath(value)
    _require(path.is_absolute() and str(path) == value and ".." not in path.parts,
             "Unix endpoint must be canonical absolute path")
    return value


def _expected(transport, listen, upstream):
    _require(type(transport) is str and transport in ("tcp", "unix_cdh_rpc"), "unsupported transport")
    if transport == "tcp":
        listen, upstream = _tcp_endpoint(listen), _tcp_endpoint(upstream)
    else:
        listen, upstream = _unix_endpoint(listen), _unix_endpoint(upstream)
        _require(PurePosixPath(listen).parent == PurePosixPath(upstream).parent,
                 "Unix endpoints must share the declared private directory")
    _require(listen != upstream, "listen and upstream must differ")
    return listen, upstream


def _error_list(value, issues, where):
    _require(type(value) is list, "errors must be a list")
    for error in value:
        _keys(error, {"type", "message"})
        _require(type(error["type"]) is str and error["type"] and type(error["message"]) is str,
                 "invalid error descriptor")
        kind = error["type"]
        category = ("TIMEOUT" if "Timeout" in kind else
                    "STOPPED" if kind in {"CancelledError", "ShutdownWithActiveConnections"} else
                    "NO_TRAFFIC" if kind == "NoConnections" else "RECORDED_ERROR")
        issues.add(f"{where}: recorded {kind}: {error['message']}", category)


def _endpoint_records(session, ready, transport, listen, upstream):
    extra = {"private_socket_dir", "scope"} if transport == "unix_cdh_rpc" else set()
    _keys(session, {"schema", "state", "started_unix_ns", "transport", "listen", "upstream",
                    "idle_timeout_seconds", "connect_timeout_seconds", "max_bytes_per_direction", "boundary"} | extra)
    _keys(ready, {"transport", "listen", "upstream"} | extra)
    _require(session["schema"] == "attestflow-loopback-relay-v1" and
             session["state"] == "STARTED_NOT_COMPLETE", "unsupported SESSION schema/state")
    _require(session["transport"] == ready["transport"] == transport, "transport mismatch")
    _require(_integer(session["started_unix_ns"]), "invalid session start timestamp")
    _require(type(session["boundary"]) is str, "invalid session boundary metadata")
    for key in ("idle_timeout_seconds", "connect_timeout_seconds"):
        value = session[key]
        _require(type(value) in (int, float) and value > 0, "invalid timeout configuration")
        try:
            finite = math.isfinite(value)
        except OverflowError as error:
            raise _Invalid("timeout configuration exceeds the collector's float range") from error
        _require(finite, "invalid timeout configuration")
    maximum = session["max_bytes_per_direction"]
    _require(type(maximum) is int and 0 < maximum <= MAX_RAW_BYTES, "unsupported capture limit")
    if transport == "tcp":
        configured = _tcp_endpoint(session["listen"], allow_zero=True)
        _require(configured == listen or configured == (listen[0], 0), "SESSION listener mismatch")
        _require(_tcp_endpoint(ready["listen"]) == listen, "READY listener mismatch")
        _require(_tcp_endpoint(session["upstream"]) == _tcp_endpoint(ready["upstream"]) == upstream,
                 "configured upstream mismatch")
    else:
        parent = str(PurePosixPath(listen).parent)
        for record in (session, ready):
            _require(record["listen"] == listen and record["upstream"] == upstream,
                     "Unix endpoint mismatch")
            _require(record["private_socket_dir"] == parent, "Unix private-directory mismatch")
            _require(record["scope"] == "dummy CDH RPC only; never AA GetToken", "unsupported Unix scope")


def _events(raw, streams, upstream, issues):
    counts = {d: 0 for d in DIRECTIONS}
    submitted = {d: 0 for d in DIRECTIONS}
    eof = {d: False for d in DIRECTIONS}
    write_eof = {d: False for d in DIRECTIONS}
    pending = {d: None for d in DIRECTIONS}
    state = {"counts": counts, "submitted": submitted, "eof": eof, "write_eof": write_eof,
             "connected_peer": None, "completed": False, "errors": []}
    if raw is None:
        return state
    try:
        _require(raw and raw.endswith(b"\n"), "events must be nonempty and LF-terminated")
        lines = raw.splitlines(keepends=True)
        _require(len(lines) <= MAX_EVENTS, "event count budget exceeded")
        previous_time = -1
        accepted = connected = terminal = False
        for index, line in enumerate(lines):
            _require(line.endswith(b"\n") and not line.endswith(b"\r\n"), "invalid event line framing")
            event = _json(line[:-1])
            _require(type(event) is dict, "event must be a JSON object")
            kind = event.get("event")
            schemas = {
                "ACCEPTED": set(), "UPSTREAM_CONNECTED": {"peer"},
                "CAPTURED": {"direction", "offset", "size", "sha256"},
                "WRITE_SUBMITTED": {"direction", "offset", "size"},
                "READ_EOF": {"direction"}, "WRITE_EOF_SUBMITTED": {"direction"},
                "BIDIRECTIONAL_EOF_OBSERVED": set(), "INCOMPLETE": {"error"},
            }
            _require(type(kind) is str and kind in schemas, "unknown event kind")
            _keys(event, {"event", "monotonic_ns"} | schemas[kind])
            moment = event["monotonic_ns"]
            _require(_integer(moment) and moment >= previous_time, "event time moved backwards")
            previous_time = moment
            _require(not terminal, "event after terminal event")
            if kind == "ACCEPTED":
                _require(index == 0 and not accepted, "ACCEPTED must occur once, first")
                accepted = True
                continue
            _require(accepted, "event before ACCEPTED")
            if kind == "UPSTREAM_CONNECTED":
                _require(not connected, "duplicate UPSTREAM_CONNECTED")
                peer = event["peer"]
                observed_peer = _tcp_endpoint(peer) if type(upstream) is tuple else _unix_endpoint(peer)
                _require(observed_peer == upstream,
                         "observed upstream peer differs from external endpoint")
                connected = True
                state["connected_peer"] = peer
                continue
            if kind == "INCOMPLETE":
                state["errors"].append(event["error"])
                _error_list([event["error"]], issues, "event INCOMPLETE")
                terminal = True
                continue
            _require(connected, "transport event before UPSTREAM_CONNECTED")
            if kind == "BIDIRECTIONAL_EOF_OBSERVED":
                _require(all(eof.values()) and all(write_eof.values()) and not any(pending.values()),
                         "terminal bidirectional EOF before both completed half-closes")
                terminal = state["completed"] = True
                continue
            direction = event["direction"]
            _require(type(direction) is str and direction in DIRECTIONS, "unknown event direction")
            if kind in {"CAPTURED", "WRITE_SUBMITTED"}:
                offset, size = event["offset"], event["size"]
                _require(_integer(offset) and type(size) is int and size > 0, "invalid chunk offset/size")
                _require(not eof[direction], "chunk after direction READ_EOF")
                if kind == "CAPTURED":
                    _require(pending[direction] is None, "new CAPTURED before previous WRITE_SUBMITTED")
                    _require(offset == counts[direction], "noncontiguous CAPTURED offset")
                    data = streams[direction]
                    _require(data is not None and offset + size <= len(data), "CAPTURED exceeds raw bytes")
                    digest = event["sha256"]
                    _require(type(digest) is str and DIGEST.fullmatch(digest) is not None and
                             hashlib.sha256(data[offset:offset + size]).hexdigest() == digest,
                             "CAPTURED raw-slice digest mismatch")
                    counts[direction] += size
                    pending[direction] = (offset, size)
                else:
                    _require(pending[direction] == (offset, size), "WRITE_SUBMITTED does not match pending CAPTURED")
                    _require(offset == submitted[direction], "noncontiguous WRITE_SUBMITTED offset")
                    submitted[direction] += size
                    pending[direction] = None
            elif kind == "READ_EOF":
                _require(not eof[direction] and pending[direction] is None, "duplicate/premature READ_EOF")
                eof[direction] = True
            else:
                _require(eof[direction] and not write_eof[direction], "WRITE_EOF_SUBMITTED without unique READ_EOF")
                write_eof[direction] = True
        _require(accepted, "missing ACCEPTED")
        if not state["completed"]:
            issues.add("events: no completed bidirectional EOF", "INCOMPLETE_TRANSPORT")
    except _Invalid as error:
        issues.add(f"events: {error}")
    return state


def _connection(root, name, reader, expected_upstream, transport, session, result_end):
    issues = _Issues()
    directory = root / name
    wanted = {"START.json", "END.json", "events.jsonl"} | {d + ".bin" for d in DIRECTIONS}
    try:
        _require(stat.S_ISDIR(directory.lstat().st_mode), "connection entry is not a real directory")
        actual = {path.name for path in directory.iterdir()}
        if actual != wanted:
            issues.add(f"{name}: missing/extra directory entries: {sorted(actual ^ wanted)}", "INVENTORY_MISMATCH")
    except (OSError, _Invalid) as error:
        issues.add(f"{name}: {error}")
        return ConnectionEvidence(name, None, None, False, False, False, False, {}, {},
                                  tuple(sorted(issues.classes)), tuple(issues.reasons)), None
    start = reader.record(directory / "START.json", issues)
    end = reader.record(directory / "END.json", issues)
    streams = {d: reader.bytes(directory / (d + ".bin"), issues, MAX_RAW_BYTES) for d in DIRECTIONS}
    events = _events(reader.bytes(directory / "events.jsonl", issues), streams, expected_upstream, issues)
    try:
        _keys(start, {"connection_id", "started_unix_ns", "client_peer"})
        _keys(end, {"connection_id", "capture_complete", "started_unix_ns", "client_peer", "directions",
                    "errors", "ended_unix_ns"}, {"upstream_peer"})
        _require(start["connection_id"] == end["connection_id"] == name, "connection identifier mismatch")
        _require(_same_json(start["started_unix_ns"], end["started_unix_ns"]) and
                 _same_json(start["client_peer"], end["client_peer"]), "START/END association mismatch")
        _require(_integer(start["started_unix_ns"]) and _integer(end["ended_unix_ns"]) and
                 start["started_unix_ns"] <= end["ended_unix_ns"], "invalid connection timestamps")
        if type(session) is dict and _integer(session.get("started_unix_ns")):
            _require(session["started_unix_ns"] <= start["started_unix_ns"], "connection predates session")
        if _integer(result_end):
            _require(end["ended_unix_ns"] <= result_end, "connection ends after RESULT")
        if transport == "tcp":
            _tcp_endpoint(start["client_peer"])
        else:
            _require(start["client_peer"] is None or type(start["client_peer"]) is str, "invalid Unix client peer")
        _require(_same_json(end.get("upstream_peer"), events["connected_peer"]) and events["connected_peer"] is not None,
                 "END/upstream connection association missing or inconsistent")
        _error_list(end["errors"], issues, "END")
        _require(all(error in end["errors"] for error in events["errors"]), "INCOMPLETE error missing from END")
        _keys(end["directions"], set(DIRECTIONS))
        for direction in DIRECTIONS:
            stats = end["directions"][direction]
            _keys(stats, {"read_bytes", "submitted_bytes", "eof_observed", "write_eof_submitted",
                          "captured_file_bytes", "captured_file_sha256"})
            _require(all(_integer(stats[k]) for k in ("read_bytes", "submitted_bytes", "captured_file_bytes")),
                     "invalid direction byte counts")
            _require(type(stats["eof_observed"]) is bool and type(stats["write_eof_submitted"]) is bool,
                     "EOF metadata must use strict booleans")
            data = streams[direction]
            _require(data is not None, "raw direction bytes unavailable")
            _require(stats["captured_file_bytes"] == len(data) and
                     stats["captured_file_sha256"] == hashlib.sha256(data).hexdigest(),
                     f"{direction}: END raw length/digest mismatch")
            _require(stats["read_bytes"] == events["counts"][direction] == len(data),
                     f"{direction}: raw/read/CAPTURED counts disagree")
            _require(stats["submitted_bytes"] == events["submitted"][direction] == len(data),
                     f"{direction}: raw/submitted/WRITE_SUBMITTED counts disagree")
            if type(session) is dict and type(session.get("max_bytes_per_direction")) is int:
                _require(len(data) <= session["max_bytes_per_direction"], "capture exceeds configured limit")
            _require(stats["eof_observed"] is events["eof"][direction] and
                     stats["write_eof_submitted"] is events["write_eof"][direction], "END/event EOF mismatch")
        _require(type(end["capture_complete"]) is bool, "END completeness must be a strict boolean")
        if not events["completed"] or not end["capture_complete"]:
            issues.add("END/events do not both claim derived complete transport", "INCOMPLETE_TRANSPORT")
    except _Invalid as error:
        issues.add(f"{name}: {error}")
    complete = not issues.reasons
    return ConnectionEvidence(name, streams[DIRECTIONS[0]], streams[DIRECTIONS[1]], complete, False,
                              events["eof"][DIRECTIONS[0]], events["eof"][DIRECTIONS[1]],
                              dict(events["counts"]), dict(events["submitted"]),
                              tuple(sorted(issues.classes)), tuple(issues.reasons)), end


def validate_relay_directory(directory: Path, *, expected_transport, expected_listen, expected_upstream) -> RelayEvidence:
    """Validate an existing relay directory without changing it.

    Three expected values are mandatory external runner inputs, never copied from
    SESSION/READY by this function. TCP expects the actual allocated listener port;
    SESSION's requested port 0 is allowed only with exact READY/external agreement.
    A failed session invalidates admission for *all* its connections, while raw
    bytes and `locally_complete` diagnostics are retained. No negative effect is
    inferred, even for complete zero-byte transport connections.
    """
    if not isinstance(directory, Path):
        raise TypeError("directory must be a pathlib.Path")
    try:
        listen, upstream = _expected(expected_transport, expected_listen, expected_upstream)
    except _Invalid as error:
        raise ValueError(f"invalid external endpoint specification: {error}") from error
    issues = _Issues()
    root = directory.absolute()
    reader = _Reader(root)
    names = []
    try:
        _require(stat.S_ISDIR(root.lstat().st_mode), "capture root must be a real directory, not a symlink")
        entries = list(root.iterdir())
        _require(len(entries) <= MAX_CONNECTIONS + 3, "directory-entry budget exceeded")
        names = sorted(path.name for path in entries if CONNECTION_NAME.fullmatch(path.name))
        wanted = {"SESSION.json", "READY.json", "RESULT.json"} | set(names)
        actual = {path.name for path in entries}
        if actual != wanted:
            issues.add(f"root missing/extra entries: {sorted(actual ^ wanted)}", "INVENTORY_MISMATCH")
        if names != [f"connection-{n:06d}" for n in range(1, len(names) + 1)]:
            issues.add("connection directory numbering is not contiguous from 000001")
    except (OSError, _Invalid) as error:
        issues.add(f"capture directory: {error}", "MISSING_RECORD" if isinstance(error, FileNotFoundError) else "INVALID_EVIDENCE")
        return RelayEvidence(False, expected_transport, listen, upstream, (), tuple(sorted(issues.classes)),
                             tuple(issues.reasons), reader.hashes)
    session = reader.record(root / "SESSION.json", issues)
    ready = reader.record(root / "READY.json", issues)
    result = reader.record(root / "RESULT.json", issues)
    try:
        _endpoint_records(session, ready, expected_transport, listen, upstream)
    except _Invalid as error:
        issues.add(f"SESSION/READY: {error}")
    result_end = result.get("ended_unix_ns") if type(result) is dict else None
    connections, ends = [], []
    for name in names:
        connection, end = _connection(root, name, reader, upstream, expected_transport, session, result_end)
        connections.append(connection)
        ends.append(end)
    try:
        _keys(result, {"schema", "capture_complete", "connection_count", "connections", "errors",
                       "ended_unix_ns", "boundary"})
        _require(result["schema"] == "attestflow-loopback-relay-result-v1", "unsupported RESULT schema")
        _require(type(result["capture_complete"]) is bool, "RESULT completeness must be a strict boolean")
        _require(type(result["connection_count"]) is int and result["connection_count"] == len(names),
                 "RESULT/directory connection count mismatch")
        _require(type(result["connections"]) is list and len(result["connections"]) == len(names),
                 "RESULT connection record count mismatch")
        _require(_same_json(result["connections"], ends), "RESULT connection records do not match individual END files")
        _require(_integer(result_end) and type(result["boundary"]) is str, "invalid RESULT timestamp/boundary")
        if type(session) is dict and _integer(session.get("started_unix_ns")):
            _require(session["started_unix_ns"] <= result_end, "RESULT predates SESSION")
        _error_list(result["errors"], issues, "RESULT")
        if not result["capture_complete"]:
            issues.add("RESULT records incomplete capture", "INCOMPLETE_TRANSPORT")
    except _Invalid as error:
        issues.add(f"RESULT: {error}")
    if not connections:
        issues.add("no captured connections; not application absence evidence", "NO_TRAFFIC")
    for connection in connections:
        if not connection.locally_complete:
            issues.add(f"{connection.connection_id}: unqualified local capture", "INCOMPLETE_CONNECTION")
            issues.classes.update(connection.classifications)
    qualified = bool(connections) and not issues.reasons and all(c.locally_complete for c in connections)
    finalized = []
    for connection in connections:
        reasons = connection.reasons + (() if qualified else ("whole relay session is unqualified",))
        classes = connection.classifications + (() if qualified else ("SESSION_UNQUALIFIED",))
        finalized.append(replace(connection, qualified=qualified, reasons=reasons, classifications=classes))
    return RelayEvidence(qualified, expected_transport, listen, upstream, tuple(finalized),
                         tuple(sorted(issues.classes)), tuple(issues.reasons), dict(reader.hashes))
