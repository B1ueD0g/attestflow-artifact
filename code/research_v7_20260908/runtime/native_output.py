"""Strict, label-independent decoder for pinned ttrpc-cdh-tool stdout.

This module does not import fixtures, read files, authenticate the capture's
origin, or infer EAR. A caller must separately establish the process/operation
association. A nonzero exit or a panic is not proof of a closed server error.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import Enum
import hashlib
import json


MAX_CAPTURE_BYTES = 4 * 1024 * 1024


class OutputKind(str, Enum):
    SUCCESS_BYTES_OBSERVED = "SUCCESS_BYTES_OBSERVED"
    NATIVE_PROCESS_ERROR = "NATIVE_PROCESS_ERROR"
    INVALID_SUCCESS_ENCODING = "INVALID_SUCCESS_ENCODING"
    UNKNOWN = "UNKNOWN"


class WireFormatError(ValueError):
    """The bytes do not have the pinned output wire format."""


def require_bool(value: object, name: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{name} must be a strict bool")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WireFormatError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(raw: bytes) -> object:
    if type(raw) is not bytes:
        raise TypeError("JSON input must be bytes")
    if len(raw) > MAX_CAPTURE_BYTES:
        raise WireFormatError("JSON size budget exceeded")
    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                WireFormatError(f"non-finite JSON constant: {value}")
            ),
        )
    except WireFormatError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise WireFormatError("invalid UTF-8 JSON") from exc


def standard_base64(raw: bytes) -> bytes:
    if type(raw) is not bytes:
        raise TypeError("base64 input must be bytes")
    if not raw or len(raw) > MAX_CAPTURE_BYTES:
        raise WireFormatError("empty or oversized base64 value")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise WireFormatError("invalid STANDARD base64") from exc
    if base64.b64encode(decoded) != raw:
        raise WireFormatError("noncanonical STANDARD base64")
    return decoded


def decode_success_line(stdout: bytes) -> tuple[bytes, bytes]:
    """Return (raw reply JSON, actual optsdata), never an expected value.

    The native println! has exactly one terminal LF. Extra lines, CRLF, spaces,
    duplicate fields, unknown fields, booleans, floats and out-of-range bytes are
    rejected instead of searching arbitrary logs for a plausible success.
    """
    if type(stdout) is not bytes:
        raise TypeError("stdout must be bytes")
    if not stdout.endswith(b"\n") or stdout.count(b"\n") != 1:
        raise WireFormatError("expected one complete LF-terminated native line")
    raw = standard_base64(stdout[:-1])
    obj = strict_json(raw)
    if type(obj) is not dict or set(obj) != {"keyunwrapresults"}:
        raise WireFormatError("unexpected KeyUnwrapOutput object")
    inner = obj["keyunwrapresults"]
    if type(inner) is not dict or set(inner) != {"optsdata"}:
        raise WireFormatError("unexpected KeyUnwrapResults object")
    values = inner["optsdata"]
    if type(values) is not list or any(type(v) is not int or not 0 <= v <= 255 for v in values):
        raise WireFormatError("optsdata must be a JSON array of strict u8 integers")
    return raw, bytes(values)


@dataclass(frozen=True)
class NativeObservation:
    operation_id: str
    kind: OutputKind
    successful_output: bool | None
    output_bytes: bytes | None
    reply_json: bytes | None
    returncode: int | None
    process_closed: bool
    capture_complete: bool
    stdout_sha256: str
    stderr_sha256: str
    diagnostic: str
    rpc_error_candidate: bool


def decode_native_capture(
    *, operation_id: str, stdout: bytes, stderr: bytes,
    returncode: int | None, process_closed: bool, capture_complete: bool,
) -> NativeObservation:
    """Decode captured native output; no case/fixture/EAR inputs are accepted.

    A complete positive output line remains positive after a later crash or in a
    still-open process. Such process/capture defects remain explicit. Absence of
    stdout, even with panic/RpcStatus, never establishes successful_output=False.
    A separate qualified RPC completion record is needed for that negative fact.
    """
    if type(operation_id) is not str or not operation_id.strip():
        raise ValueError("a nonempty operation_id is required")
    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise TypeError("stdout/stderr must be raw bytes")
    if max(len(stdout), len(stderr)) > MAX_CAPTURE_BYTES:
        raise ValueError("capture size budget exceeded")
    require_bool(process_closed, "process_closed")
    require_bool(capture_complete, "capture_complete")
    if returncode is not None and type(returncode) is not int:
        raise TypeError("returncode must be int or None, not bool")
    if process_closed != (returncode is not None):
        raise ValueError("closed process must have a returncode; open process must not")
    rpc_candidate = b"request to CDH: RpcStatus(" in stderr
    output = reply = None
    successful_output = None
    if stdout:
        try:
            reply, output = decode_success_line(stdout)
        except WireFormatError as exc:
            kind = OutputKind.INVALID_SUCCESS_ENCODING
            diagnostic = str(exc)
        else:
            kind = OutputKind.SUCCESS_BYTES_OBSERVED
            successful_output = True
            diagnostic = "actual complete success payload observed"
            if not process_closed or returncode != 0 or not capture_complete:
                diagnostic += "; process/capture not a clean completed success"
            if rpc_candidate:
                diagnostic += "; contradictory RPC-error candidate also retained"
    elif process_closed and returncode != 0:
        kind = OutputKind.NATIVE_PROCESS_ERROR
        diagnostic = "nonzero exit without success payload; RPC completion/effect unknown"
    else:
        kind = OutputKind.UNKNOWN
        diagnostic = "no complete native success payload; output absence is not a negative fact"
    return NativeObservation(
        operation_id, kind, successful_output, output, reply, returncode,
        process_closed, capture_complete, hashlib.sha256(stdout).hexdigest(),
        hashlib.sha256(stderr).hexdigest(), diagnostic, rpc_candidate,
    )
