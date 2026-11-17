"""Conservative offline HTTP/1 byte framing for one isolated dummy connection.

No network, file I/O, JWT verification, case labels, policy decisions or EAR
truth inference. Capture/process origin and cross-connection association are the
caller's responsibility. See HTTP_OBSERVATION_DESIGN.md for the bounded subset.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import re


MAX_STREAM_BYTES = 16 << 20
MAX_BODY_BYTES = 4 << 20
MAX_HEADER_BYTES = 64 << 10
MAX_LINE_BYTES = 16 << 10
MAX_FIELDS = 256
MAX_MESSAGES = 4096
MAX_INTERIM = 32
MAX_CHUNKS = 65536
TOKEN = rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
TOKEN_RE = re.compile(TOKEN)
CRITICAL = frozenset({b"content-length", b"transfer-encoding", b"authorization",
                      b"cookie", b"host", b"connection", b"trailer", b"upgrade"})
FORBIDDEN_TRAILERS = CRITICAL | {b"content-encoding", b"content-type", b"content-range"}


class ParseState(str, Enum):
    COMPLETE = "COMPLETE"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class ParseIssue:
    state: ParseState
    direction: str
    offset: int
    code: str
    detail: str


@dataclass(frozen=True)
class Header:
    name: bytes  # original case, not silently merged
    value: bytes  # excludes surrounding OWS; raw includes the original bytes
    start: int
    end: int
    raw: bytes


@dataclass(frozen=True)
class ChunkSpan:
    start: int
    data_start: int
    data_end: int
    end: int
    extension: bytes


@dataclass(frozen=True)
class HttpMessage:
    direction: str
    start: int
    header_end: int
    end: int
    raw: bytes
    raw_sha256: str
    version: str
    method: str | None
    target: str | None
    path: str | None  # origin path only, query not included; no URL decoding
    status: int | None
    reason: bytes | None
    headers: tuple[Header, ...]
    duplicate_headers: tuple[bytes, ...]
    body: bytes  # dechunked only; content-encoding is NOT decoded
    wire_body: bytes
    framing: str
    chunks: tuple[ChunkSpan, ...]
    trailers: tuple[Header, ...]
    authorization: bytes | None
    bearer_token: bytes | None
    authorization_kind: str
    cookie: bytes | None
    connection_close: bool

    def header_values(self, name: bytes) -> tuple[bytes, ...]:
        if type(name) is not bytes:
            raise TypeError("header name must be bytes")
        return tuple(h.value for h in self.headers if h.name.lower() == name.lower())


@dataclass(frozen=True)
class Exchange:
    sequence: int
    request: HttpMessage
    interim_responses: tuple[HttpMessage, ...]
    response: HttpMessage | None
    pairing_qualified: bool


@dataclass(frozen=True)
class ConnectionParse:
    connection_id: str
    state: ParseState
    exchanges: tuple[Exchange, ...]
    issues: tuple[ParseIssue, ...]
    client_consumed: int
    server_consumed: int
    client_raw: bytes
    server_raw: bytes
    client_sha256: str
    server_sha256: str
    client_capture_complete: bool
    server_capture_complete: bool
    server_eof: bool


class _Stop(Exception):
    def __init__(self, state: ParseState, offset: int, code: str, detail: str):
        self.state, self.offset, self.code, self.detail = state, offset, code, detail


def _stop(state: ParseState, offset: int, code: str, detail: str) -> None:
    raise _Stop(state, offset, code, detail)


def _line(data: bytes, offset: int) -> tuple[bytes, int]:
    end = data.find(b"\r\n", offset)
    bare_lf = data.find(b"\n", offset)
    if bare_lf >= 0 and (end < 0 or bare_lf != end + 1):
        _stop(ParseState.INVALID, bare_lf, "BARE_LF", "strict CRLF framing required")
    if end < 0:
        if len(data) - offset > MAX_LINE_BYTES:
            _stop(ParseState.UNSUPPORTED, offset, "LINE_BUDGET", "line exceeds local budget")
        _stop(ParseState.UNKNOWN, offset, "INCOMPLETE_LINE", "complete CRLF line not captured")
    if end - offset > MAX_LINE_BYTES:
        _stop(ParseState.UNSUPPORTED, offset, "LINE_BUDGET", "line exceeds local budget")
    value = data[offset:end]
    if b"\r" in value:
        _stop(ParseState.INVALID, offset, "BARE_CR", "bare CR in protocol line")
    return value, end + 2


def _headers(data: bytes, offset: int, *, trailer: bool = False) -> tuple[tuple[Header, ...], int, tuple[bytes, ...]]:
    beginning = offset
    result: list[Header] = []
    counts: dict[bytes, int] = {}
    while True:
        line, end = _line(data, offset)
        if end - beginning > MAX_HEADER_BYTES:
            _stop(ParseState.UNSUPPORTED, offset, "HEADER_BUDGET", "header section exceeds budget")
        if not line:
            duplicates = tuple(sorted(name for name, count in counts.items() if count > 1))
            return tuple(result), end, duplicates
        if len(result) >= MAX_FIELDS:
            _stop(ParseState.UNSUPPORTED, offset, "FIELD_BUDGET", "too many header fields")
        if line[:1] in (b" ", b"\t"):
            _stop(ParseState.INVALID, offset, "OBS_FOLD", "folded/whitespace-prefixed fields are not normalized")
        name, separator, raw_value = line.partition(b":")
        if not separator or TOKEN_RE.fullmatch(name) is None:
            _stop(ParseState.INVALID, offset, "INVALID_FIELD_NAME", "invalid field name or whitespace before colon")
        if any(byte < 32 and byte != 9 or byte == 127 for byte in raw_value):
            _stop(ParseState.INVALID, offset, "INVALID_FIELD_VALUE", "control byte in field value")
        lower = name.lower()
        counts[lower] = counts.get(lower, 0) + 1
        if counts[lower] > 1 and lower in CRITICAL:
            _stop(ParseState.INVALID, offset, "DUPLICATE_CRITICAL_HEADER", lower.decode("ascii"))
        if trailer and lower in FORBIDDEN_TRAILERS:
            _stop(ParseState.INVALID, offset, "FORBIDDEN_TRAILER", lower.decode("ascii"))
        result.append(Header(name, raw_value.strip(b" \t"), offset, end, data[offset:end]))
        offset = end


def _one(headers: tuple[Header, ...], name: bytes) -> bytes | None:
    return next((h.value for h in headers if h.name.lower() == name), None)


def _chunk_size(line: bytes, offset: int) -> tuple[int, bytes]:
    match = re.match(rb"[0-9A-Fa-f]+", line)
    if match is None:
        _stop(ParseState.INVALID, offset, "INVALID_CHUNK_SIZE", "hexadecimal chunk size required")
    digits = match.group()
    if len(digits) > 16:
        _stop(ParseState.UNSUPPORTED, offset, "CHUNK_SIZE_BUDGET", "chunk size numeral exceeds budget")
    size = int(digits, 16)
    if size > MAX_BODY_BYTES:
        _stop(ParseState.UNSUPPORTED, offset, "BODY_BUDGET", "chunk exceeds body budget")
    extension = line[match.end():]
    p = match.end()
    # Parse chunk extensions rather than splitting blindly at ';' inside quotes.
    while p < len(line):
        while p < len(line) and line[p] in (32, 9):
            p += 1
        if p == len(line) or line[p] != 59:
            _stop(ParseState.INVALID, offset + p, "INVALID_CHUNK_EXTENSION", "semicolon required")
        p += 1
        while p < len(line) and line[p] in (32, 9):
            p += 1
        token = TOKEN_RE.match(line, p)
        if token is None:
            _stop(ParseState.INVALID, offset + p, "INVALID_CHUNK_EXTENSION", "extension name required")
        p = token.end()
        while p < len(line) and line[p] in (32, 9):
            p += 1
        if p < len(line) and line[p] == 61:
            p += 1
            while p < len(line) and line[p] in (32, 9):
                p += 1
            if p < len(line) and line[p] == 34:
                p += 1
                while p < len(line) and line[p] != 34:
                    byte = line[p]
                    if byte == 92:
                        p += 1
                        if p == len(line):
                            _stop(ParseState.INVALID, offset + p, "INVALID_CHUNK_EXTENSION", "unfinished quoted escape")
                        byte = line[p]
                    if byte < 32 and byte != 9 or byte == 127:
                        _stop(ParseState.INVALID, offset + p, "INVALID_CHUNK_EXTENSION", "invalid quoted byte")
                    p += 1
                if p == len(line):
                    _stop(ParseState.INVALID, offset + p, "INVALID_CHUNK_EXTENSION", "unterminated quote")
                p += 1
            else:
                token = TOKEN_RE.match(line, p)
                if token is None:
                    _stop(ParseState.INVALID, offset + p, "INVALID_CHUNK_EXTENSION", "extension value required")
                p = token.end()
    return size, extension


def _chunked(data: bytes, offset: int) -> tuple[bytes, int, tuple[ChunkSpan, ...], tuple[Header, ...]]:
    pieces: list[bytes] = []
    spans: list[ChunkSpan] = []
    size_total = 0
    for _ in range(MAX_CHUNKS):
        start = offset
        line, after_size = _line(data, offset)
        size, extension = _chunk_size(line, start)
        if size == 0:
            trailers, end, _duplicates = _headers(data, after_size, trailer=True)
            spans.append(ChunkSpan(start, after_size, after_size, after_size, extension))
            return b"".join(pieces), end, tuple(spans), trailers
        size_total += size
        if size_total > MAX_BODY_BYTES:
            _stop(ParseState.UNSUPPORTED, start, "BODY_BUDGET", "dechunked body exceeds budget")
        end = after_size + size
        if len(data) < end + 2:
            _stop(ParseState.UNKNOWN, after_size, "INCOMPLETE_CHUNK", "chunk data or terminator missing")
        if data[end:end + 2] != b"\r\n":
            _stop(ParseState.INVALID, end, "INVALID_CHUNK_TERMINATOR", "chunk data must end in CRLF")
        pieces.append(data[after_size:end])
        spans.append(ChunkSpan(start, after_size, end, end + 2, extension))
        offset = end + 2
    _stop(ParseState.UNSUPPORTED, offset, "CHUNK_COUNT_BUDGET", "too many chunks")


def _message(data: bytes, start: int, *, direction: str, request_method: str | None = None,
             server_eof: bool = False) -> HttpMessage:
    line, offset = _line(data, start)
    method = target = path = status = reason = None
    if direction == "client_to_server":
        match = re.fullmatch(rb"(" + TOKEN + rb") ([\x21-\x7e]+) (HTTP/[0-9]\.[0-9])", line)
        if match is None:
            _stop(ParseState.INVALID, start, "INVALID_REQUEST_LINE", "strict HTTP/1.0 or 1.1 request line required")
        method, target, version = (x.decode("ascii") for x in match.groups())
        if version not in ("HTTP/1.0", "HTTP/1.1"):
            _stop(ParseState.UNSUPPORTED, start, "HTTP_VERSION_UNSUPPORTED", "only HTTP/1.0 and HTTP/1.1 supported")
        if method == "CONNECT":
            _stop(ParseState.UNSUPPORTED, start, "CONNECT_UNSUPPORTED", "no tunnel interpretation")
        if target == "*" and method == "OPTIONS":
            path = "*"
        elif target.startswith("/") and "#" not in target:
            path = target.partition("?")[0]
        else:
            _stop(ParseState.UNSUPPORTED, start, "TARGET_FORM_UNSUPPORTED", "only origin-form or OPTIONS * supported")
    else:
        match = re.fullmatch(rb"(HTTP/[0-9]\.[0-9]) ([0-9]{3}) ([\x09\x20-\x7e\x80-\xff]*)", line)
        if match is None:
            _stop(ParseState.INVALID, start, "INVALID_STATUS_LINE", "strict HTTP/1 status line required")
        version, status_raw, reason = match.groups()
        version, status = version.decode("ascii"), int(status_raw)
        if version not in ("HTTP/1.0", "HTTP/1.1"):
            _stop(ParseState.UNSUPPORTED, start, "HTTP_VERSION_UNSUPPORTED", "only HTTP/1.0 and HTTP/1.1 supported")
        if not 100 <= status <= 599:
            _stop(ParseState.INVALID, start, "STATUS_RANGE", "status outside supported HTTP classes")
        if status == 101:
            _stop(ParseState.UNSUPPORTED, start, "UPGRADE_UNSUPPORTED", "101 changes the protocol; do not resynchronize")
    headers, header_end, duplicates = _headers(data, offset)
    if direction == "client_to_server" and version == "HTTP/1.1" and _one(headers, b"host") is None:
        _stop(ParseState.INVALID, start, "MISSING_HOST", "HTTP/1.1 request has no Host")
    te, cl = _one(headers, b"transfer-encoding"), _one(headers, b"content-length")
    if te is not None and cl is not None:
        _stop(ParseState.INVALID, start, "TE_CL_CONFLICT", "do not choose between conflicting lengths")
    length = None
    if cl is not None:
        if re.fullmatch(rb"[0-9]+", cl) is None:
            _stop(ParseState.INVALID, start, "INVALID_CONTENT_LENGTH", "one decimal length only; no lists/signs")
        if len(cl) > 20:
            _stop(ParseState.UNSUPPORTED, start, "LENGTH_NUMERAL_BUDGET", "length numeral exceeds budget")
        length = int(cl)
    if te is not None:
        if version != "HTTP/1.1" or te.lower() != b"chunked":
            _stop(ParseState.UNSUPPORTED, start, "TRANSFER_CODING_UNSUPPORTED", "only single HTTP/1.1 chunked coding supported")
    if status is not None and (100 <= status < 200 or status == 204) and (cl is not None or te is not None):
        _stop(ParseState.INVALID, start, "FORBIDDEN_LENGTH_HEADER", "1xx/204 must not carry these framing headers")
    no_body = direction == "server_to_client" and (request_method == "HEAD" or status in (204, 304) or status < 200)
    chunks: tuple[ChunkSpan, ...] = ()
    trailers: tuple[Header, ...] = ()
    if no_body:
        body, end, framing = b"", header_end, "NO_BODY_BY_METHOD_OR_STATUS"
    elif te is not None:
        body, end, chunks, trailers = _chunked(data, header_end)
        framing = "CHUNKED"
    elif length is not None:
        if length > MAX_BODY_BYTES:
            _stop(ParseState.UNSUPPORTED, header_end, "BODY_BUDGET", "content-length exceeds budget")
        end = header_end + length
        if end > len(data):
            _stop(ParseState.UNKNOWN, header_end, "INCOMPLETE_CONTENT_LENGTH", "declared body bytes missing")
        body, framing = data[header_end:end], "CONTENT_LENGTH"
    elif direction == "client_to_server":
        body, end, framing = b"", header_end, "NO_REQUEST_BODY_FRAMING"
    else:
        if not server_eof:
            _stop(ParseState.UNKNOWN, header_end, "CLOSE_DELIMITED_WITHOUT_EOF", "clean server EOF must be supplied independently")
        if len(data) - header_end > MAX_BODY_BYTES:
            _stop(ParseState.UNSUPPORTED, header_end, "BODY_BUDGET", "close-delimited body exceeds budget")
        body, end, framing = data[header_end:], len(data), "CLOSE_DELIMITED"
    connection = _one(headers, b"connection")
    connection_tokens = () if connection is None else tuple(x.strip(b" \t").lower() for x in connection.split(b","))
    if any(TOKEN_RE.fullmatch(x) is None for x in connection_tokens):
        _stop(ParseState.INVALID, start, "INVALID_CONNECTION_OPTIONS", "invalid connection option list")
    connection_close = b"close" in connection_tokens or (version == "HTTP/1.0" and b"keep-alive" not in connection_tokens)
    authorization, cookie = _one(headers, b"authorization"), _one(headers, b"cookie")
    bearer_token, authorization_kind = None, "ABSENT"
    if authorization is not None:
        bearer = re.fullmatch(rb"(?i:Bearer) +([A-Za-z0-9\-._~+/]+=*)", authorization)
        if bearer:
            bearer_token, authorization_kind = bearer.group(1), "BEARER_TOKEN68_SYNTAX_ONLY"
        else:
            authorization_kind = "OTHER_OR_UNSUPPORTED_AUTHORIZATION_SYNTAX"
    raw = data[start:end]
    return HttpMessage(direction, start, header_end, end, raw, hashlib.sha256(raw).hexdigest(),
                       version, method, target, path, status, reason, headers, duplicates,
                       body, data[header_end:end], framing, chunks, trailers, authorization,
                       bearer_token, authorization_kind, cookie, connection_close)


def parse_http1_connection(
    *, connection_id: str, client_to_server: bytes, server_to_client: bytes,
    client_capture_complete: bool, server_capture_complete: bool, server_eof: bool = False,
) -> ConnectionParse:
    """Frame and FIFO-pair one connection's raw directional streams.

    complete flags assert no missing/injected bytes from the connection start;
    they are caller assumptions, not facts established by this parser. If false,
    parses remain diagnostic candidates and every pairing_qualified is false.
    server_eof means witnessed clean directional EOF, not a timeout or collector
    shutdown. Complete frames before a later failure remain visible; no recovery
    scan guesses where a subsequent message might begin.
    """
    if type(connection_id) is not str or not connection_id.strip():
        raise ValueError("nonempty connection_id required")
    for name, data in (("client_to_server", client_to_server), ("server_to_client", server_to_client)):
        if type(data) is not bytes:
            raise TypeError(f"{name} must be bytes")
        if len(data) > MAX_STREAM_BYTES:
            raise ValueError(f"{name} exceeds stream budget")
    for name, flag in (("client_capture_complete", client_capture_complete),
                       ("server_capture_complete", server_capture_complete), ("server_eof", server_eof)):
        if type(flag) is not bool:
            raise TypeError(f"{name} must be a strict bool")
    issues: list[ParseIssue] = []
    qualified = client_capture_complete and server_capture_complete
    if not qualified:
        issues.append(ParseIssue(ParseState.UNKNOWN, "both", 0, "CAPTURE_UNQUALIFIED",
                                 "directional gap-free origin/completeness not asserted"))
    requests: list[HttpMessage] = []
    client_offset = server_offset = 0
    while client_offset < len(client_to_server):
        try:
            if len(requests) >= MAX_MESSAGES:
                _stop(ParseState.UNSUPPORTED, client_offset, "MESSAGE_BUDGET", "too many requests")
            request = _message(client_to_server, client_offset, direction="client_to_server")
        except _Stop as exc:
            issues.append(ParseIssue(exc.state, "client_to_server", exc.offset, exc.code, exc.detail))
            break
        requests.append(request)
        client_offset = request.end
    exchanges: list[Exchange] = []
    response_stopped = False
    for index, request in enumerate(requests):
        interim: list[HttpMessage] = []
        response = None
        if not response_stopped:
            try:
                while True:
                    if server_offset == len(server_to_client):
                        _stop(ParseState.UNKNOWN, server_offset, "MISSING_FINAL_RESPONSE", "no complete final response captured")
                    candidate = _message(server_to_client, server_offset, direction="server_to_client",
                                         request_method=request.method,
                                         server_eof=server_eof and server_capture_complete)
                    server_offset = candidate.end
                    if candidate.status < 200:
                        interim.append(candidate)
                        if len(interim) > MAX_INTERIM:
                            _stop(ParseState.UNSUPPORTED, server_offset, "INTERIM_BUDGET", "too many informational responses")
                    else:
                        response = candidate
                        break
            except _Stop as exc:
                issues.append(ParseIssue(exc.state, "server_to_client", exc.offset, exc.code, exc.detail))
                response_stopped = True
        exchanges.append(Exchange(index + 1, request, tuple(interim), response, qualified and response is not None))
        if response is not None and (request.connection_close or response.connection_close or response.framing == "CLOSE_DELIMITED"):
            if index + 1 < len(requests) or server_offset < len(server_to_client):
                issues.append(ParseIssue(ParseState.INVALID, "both", server_offset, "REUSE_AFTER_CLOSE",
                                         "extra exchange/data after nonpersistent response"))
            response_stopped = True
    if server_offset < len(server_to_client) and not response_stopped:
        if client_offset < len(client_to_server):
            issues.append(ParseIssue(ParseState.UNKNOWN, "server_to_client", server_offset,
                                     "UNPAIRED_RESPONSE_AFTER_REQUEST_STOP", "request framing stopped; do not guess response association"))
        else:
            issues.append(ParseIssue(ParseState.INVALID, "server_to_client", server_offset,
                                     "UNMATCHED_RESPONSE_BYTES", "no outstanding completely parsed request; no resynchronization"))
    if not requests and not client_to_server and not server_to_client:
        issues.append(ParseIssue(ParseState.UNKNOWN, "both", 0, "EMPTY_CAPTURE", "no HTTP exchange observed"))
    rank = {ParseState.COMPLETE: 0, ParseState.UNKNOWN: 1, ParseState.UNSUPPORTED: 2, ParseState.INVALID: 3}
    state = max((issue.state for issue in issues), key=rank.get, default=ParseState.COMPLETE)
    return ConnectionParse(connection_id, state, tuple(exchanges), tuple(issues), client_offset,
                           server_offset, client_to_server, server_to_client,
                           hashlib.sha256(client_to_server).hexdigest(), hashlib.sha256(server_to_client).hexdigest(),
                           client_capture_complete, server_capture_complete, server_eof)
