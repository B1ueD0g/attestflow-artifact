"""Host-only, read-only candidate qualification; never a Phi/security verdict.

Admission values come from the caller's separately retained launch/build/fixture
checks, NOT claims copied from the run under examination. See VALIDATION_DESIGN.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import stat
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from runtime.native_output import decode_native_capture, strict_json
    from wire.ear_claims import verify_ear_with_pinned_key
    from wire.http_capture import ParseState, parse_http1_connection
    from wire.relay_evidence import validate_relay_directory
    from wire.ttrpc_capture import decode_unwrap_exchange
else:
    from ..runtime.native_output import decode_native_capture, strict_json
    from ..wire.ear_claims import verify_ear_with_pinned_key
    from ..wire.http_capture import ParseState, parse_http1_connection
    from ..wire.relay_evidence import validate_relay_directory
    from ..wire.ttrpc_capture import decode_unwrap_exchange

SCOPE = "DEVELOPMENT_SMOKE_NOT_FORMAL"
BINARY_NAMES = {"kbs", "ttrpc-aa", "ttrpc-cdh", "ttrpc-cdh-tool"}
RESOURCE_API = "/kbs/v0/resource/default/attestflow-v7/kek-a"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
BOUNDARIES = [
    "Same-team host implementation check, not external replication or native experiment.",
    "Trusted local launch/build/container/collector origin is an external admission assumption; hashes do not defeat same-root replacement.",
    "Wall validity covers the whole GET connection under explicitly admitted stable local clocks, not an exact GET Unix timestamp.",
    "No AA private-key socket capture; AA causality and source-to-binary mapping additionally depend on the admitted native launch/source chain.",
    "Resource HTTP bytes are encrypted wire response, not independently decrypted KEK; LEK is observed at RPC and CLI only.",
    "No Phi, policy-denial, vulnerability, tool-superiority, hardware or production verdict is produced.",
]


@dataclass(frozen=True)
class Admission:
    binary_sha256: dict[str, str]
    # Logical labels -> (external existing source/build-manifest path, expected SHA).
    source_files: dict[str, tuple[Path, str]]
    client_input: bytes
    reference_lek: bytes
    public_key_pem_sha256: str
    expected_issuer: str
    unix_front: str
    unix_back: str
    trusted_local_origin: bool
    stable_local_clocks: bool
    origin_note: str


class NotQualified(ValueError):
    pass


def need(value, reason):
    if not value:
        raise NotQualified(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def same_json(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def read_regular(path: Path, limit=64 << 20):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "not a bounded regular file: " + str(path))
    raw = path.read_bytes()
    need(len(raw) == info.st_size, "file changed while reading: " + str(path))
    return raw


def record(path):
    value = strict_json(read_regular(path, 4 << 20))
    need(type(value) is dict, "metadata is not an object: " + str(path))
    return value


def inventory(directory):
    need(stat.S_ISDIR(directory.lstat().st_mode), "run root must be an existing real directory")
    files = {}
    pending = [directory]
    total = 0
    entries = 0
    while pending:
        for path in pending.pop().iterdir():
            entries += 1
            need(entries <= 4096, "inventory entry budget exceeded")
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                pending.append(path)
            else:
                need(stat.S_ISREG(mode), "nonregular/symlink run entry: " + str(path))
                raw = read_regular(path)
                total += len(raw)
                need(total <= 256 << 20, "inventory byte budget exceeded")
                files[path.relative_to(directory).as_posix()] = sha(raw)
    return files


def check_manifest(directory):
    files = inventory(directory)
    need("MANIFEST.json" in files, "missing final manifest")
    manifest = record(directory / "MANIFEST.json")
    from release_inventory import retained_payload
    expected = retained_payload(directory, manifest)
    need(manifest.get("scope") == SCOPE and type(expected) is dict, "unsupported manifest")
    need({name: value for name, value in files.items() if name != "MANIFEST.json"} == expected,
         "manifest inventory/digest mismatch (extra and missing files are not ignored)")
    return files


def validate_admission(a):
    need(isinstance(a, Admission), "explicit Admission required")
    need(a.trusted_local_origin is True and a.stable_local_clocks is True,
         "trusted local origin and stable local clocks must be explicitly admitted")
    need(type(a.origin_note) is str and a.origin_note.strip(), "external origin note required")
    need(type(a.binary_sha256) is dict and set(a.binary_sha256) == BINARY_NAMES,
         "all four external binary hashes required")
    need(all(type(h) is str and DIGEST.fullmatch(h) for h in a.binary_sha256.values()), "invalid binary digest")
    need(type(a.source_files) is dict and a.source_files, "external source/build hashes required")
    for label, entry in a.source_files.items():
        need(type(label) is str and label and type(entry) in (tuple, list) and len(entry) == 2,
             "malformed source anchor")
        path, digest = entry
        need(isinstance(path, Path) and type(digest) is str and DIGEST.fullmatch(digest), "invalid source anchor")
        need(sha(read_regular(path)) == digest, "external source hash mismatch: " + label)
    need(type(a.client_input) is bytes and 0 < len(a.client_input) <= 8192, "bounded external client input required")
    need(type(a.reference_lek) is bytes and len(a.reference_lek) == 32, "host-only independent 32-byte LEK required")
    need(type(a.public_key_pem_sha256) is str and DIGEST.fullmatch(a.public_key_pem_sha256), "external public-key hash required")
    need(type(a.expected_issuer) is str and a.expected_issuer, "external expected issuer required")
    front, back = PurePosixPath(a.unix_front), PurePosixPath(a.unix_back)
    need(str(front) == a.unix_front and str(back) == a.unix_back and front.parent == back.parent
         and front.name == "front.sock" and back.name == "back.sock"
         and front.parent.parent == PurePosixPath("/tmp")
         and front.parent.name.startswith("attestflow-v7-rpc-")
         and ".." not in front.parts, "unsupported externally admitted private RPC endpoints")


def process_records(directory, result, a):
    binaries = record(directory / "BINARIES.json")
    need(set(binaries) == BINARY_NAMES, "binary inventory mismatch")
    for name in BINARY_NAMES:
        need(binaries[name]["sha256"] == a.binary_sha256[name], "binary hash mismatch: " + name)
    names = {"kbs": "kbs", "aa": "ttrpc-aa", "cdh": "ttrpc-cdh", "client": "ttrpc-cdh-tool"}
    need(set(result.get("processes", {})) == set(names), "not exactly the four admitted native processes")
    processes = {}
    for name, binary in names.items():
        item = record(directory / "processes" / name / "END.json")
        need(same_json(item, result["processes"][name]), "process END/RESULT mismatch: " + name)
        start = record(directory / "processes" / name / "START.json")
        pid_record = record(directory / "processes" / name / "PROCESS.json")
        for key in ("name", "argv", "env", "cwd", "started_unix_ns"):
            need(same_json(start[key], item[key]), "process START/END identity mismatch: " + name)
        need(start.get("pid") is None and start.get("returncode") is None
             and start.get("process_closed") is False and start.get("capture_complete") is False,
             "unsupported process START state")
        need(type(pid_record.get("pid")) is int and pid_record["pid"] == item["pid"]
             and type(pid_record.get("observed_unix_ns")) is int
             and item["started_unix_ns"] <= pid_record["observed_unix_ns"] <= item["ended_unix_ns"],
             "process PID observation not associated")
        need(item["process_closed"] is True and item["capture_complete"] is True
             and item["timed_out"] is False and item["errors"] == [], "unclean process: " + name)
        need(type(item["returncode"]) is int and type(item["pid"]) is int and item["pid"] > 0,
             "invalid native pid/returncode")
        requested_term = any(s.get("signal") == "SIGTERM" and s.get("reason") == "registered_child_cleanup"
                             for s in item["signals"])
        need(item["returncode"] == 0 or (name == "kbs" and item["returncode"] == -15 and requested_term),
             "unexpected service/client returncode: " + name)
        need(type(item["started_unix_ns"]) is int and type(item["ended_unix_ns"]) is int
             and item["started_unix_ns"] <= item["ended_unix_ns"], "invalid process interval")
        need(item["argv"][0] == binaries[binary]["path"], "argv/binary identity mismatch")
        allowed = {"PATH", "LANG", "LC_ALL", "TZ", "RUST_LOG"} | ({"AA_KBC_PARAMS"} if name == "cdh" else set())
        need(set(item["env"]) <= allowed, "unadmitted native environment variable")
        if name == "cdh":
            need(item["env"].get("AA_KBC_PARAMS") == "cc_kbc::http://127.0.0.1:8081", "effective CDH KBC mismatch")
        if name == "client":
            need(item["argv"][1:3] == ["--socket", "unix://" + a.unix_front], "client socket differs from external admission")
        for label in ("stdout", "stderr"):
            raw = read_regular(directory / "processes" / name / (label + ".bin"))
            stream = item["streams"][label]
            need(stream["eof"] is True and type(stream["bytes"]) is int and stream["bytes"] == len(raw)
                 and stream["sha256"] == sha(raw), "process raw stream mismatch")
        processes[name] = item
    need(len({p["pid"] for p in processes.values()}) == 4, "native pid reuse/duplication unsupported")
    return processes


def capture_span(directory, connection_id, direction, start, end):
    """Return actual CAPTURED monotonic interval for already-qualified offsets."""
    need(type(start) is int and type(end) is int and 0 <= start < end, "invalid message span")
    events = [strict_json(line) for line in read_regular(directory / connection_id / "events.jsonl", 4 << 20).splitlines()]
    selected = [e for e in events if e["event"] == "CAPTURED" and e["direction"] == direction
                and e["offset"] < end and e["offset"] + e["size"] > start]
    need(selected and selected[0]["offset"] <= start
         and selected[-1]["offset"] + selected[-1]["size"] >= end, "message not covered by capture offsets")
    return selected[0]["monotonic_ns"], selected[-1]["monotonic_ns"]


def http_profile(directory, tcp, public, a, diagnostics):
    exchanges = []
    for conn in tcp.connections:
        parsed = parse_http1_connection(connection_id=conn.connection_id,
            client_to_server=conn.client_to_upstream, server_to_client=conn.upstream_to_client,
            client_capture_complete=conn.qualified, server_capture_complete=conn.qualified,
            server_eof=conn.upstream_eof_observed)
        need(parsed.state == ParseState.COMPLETE and parsed.client_consumed == len(conn.client_to_upstream)
             and parsed.server_consumed == len(conn.upstream_to_client), "not every HTTP connection is completely parsed")
        for exchange in parsed.exchanges:
            req, res = exchange.request, exchange.response
            need(exchange.pairing_qualified and res is not None, "unqualified HTTP pairing")
            need(not req.header_values(b"content-encoding") and not res.header_values(b"content-encoding"), "encoded body profile unsupported")
            need(req.header_values(b"host") == (b"127.0.0.1:8081",), "actual HTTP Host mismatch")
            req_span = capture_span(directory, conn.connection_id, "client_to_upstream", req.start, req.end)
            res_span = capture_span(directory, conn.connection_id, "upstream_to_client", res.start, res.end)
            exchanges.append((conn.connection_id, req, res, req_span, res_span))
    diagnostics["http_all_connections_complete"] = True
    diagnostics["http_exchange_count"] = len(exchanges)
    diagnostics["all_get_count"] = sum(x[1].method == "GET" for x in exchanges)
    need(len(exchanges) == 3, "C01 one-handshake/one-GET profile only; retries/extra traffic require separate review")
    expected = {("POST", "/kbs/v0/auth"), ("POST", "/kbs/v0/attest"), ("GET", RESOURCE_API)}
    need({(x[1].method, x[1].target) for x in exchanges} == expected, "unknown/duplicate HTTP request profile")
    by_path = {x[1].target: x for x in exchanges}
    auth, attest, resource = (by_path[p] for p in ("/kbs/v0/auth", "/kbs/v0/attest", RESOURCE_API))
    need(all(x[2].status == 200 for x in exchanges), "C01 requires actual 200 responses; other statuses are not denial evidence")
    need(auth[4][1] <= attest[3][0] and attest[4][1] <= resource[3][0], "HTTP chronology not supported by raw event offsets")
    challenge, attestation = strict_json(auth[2].body), strict_json(attest[1].body)
    nonce = challenge.get("nonce")
    need(type(nonce) is str and nonce and attestation.get("runtime-data", {}).get("nonce") == nonce,
         "actual challenge/attestation nonce relation missing")
    # The narrow no-retry profile does not infer sessions from a label or token.
    cookies = auth[2].header_values(b"set-cookie")
    need(len(cookies) == 1, "unsupported auth session-cookie profile")
    session_pair = cookies[0].split(b";", 1)[0]
    need(b"=" in session_pair and attest[1].cookie == session_pair, "auth/attest session cookie not associated")
    token_body = strict_json(attest[2].body)
    need(type(token_body) is dict and set(token_body) == {"token"} and type(token_body["token"]) is str,
         "unsupported actual /attest token response")
    token = token_body["token"].encode("ascii")
    req = resource[1]
    need(req.cookie is None and req.bearer_token == token and req.authorization == b"Bearer " + token,
         "resource GET must use exact /attest Bearer with Cookie absent")
    connection = record(directory / resource[0] / "END.json")
    lower, upper = connection["started_unix_ns"], connection["ended_unix_ns"]
    need(type(lower) is int and type(upper) is int and 0 <= lower <= upper, "invalid GET connection wall interval")
    before = verify_ear_with_pinned_key(token=token, public_key_pem=public,
        expected_issuer=a.expected_issuer, observed_at_unix=lower // 1_000_000_000)
    after = verify_ear_with_pinned_key(token=token, public_key_pem=public,
        expected_issuer=a.expected_issuer, observed_at_unix=upper // 1_000_000_000)
    need(before.token_sha256 == after.token_sha256, "inconsistent token check")
    diagnostics.update({"resource_gets_covered": 1, "actual_cpu_ear_status": before.cpu_status,
        "token_sha256": before.token_sha256, "public_key_spki_sha256": before.public_key_spki_sha256,
        "get_connection_wall_interval_ns": [lower, upper], "cookie_absent_at_get": True,
        "actual_resource_response_sha256": sha(resource[2].body),
        "http_messages": [{"connection": cid, "method": request.method, "target": request.target,
            "status": response.status, "request_offsets": [request.start, request.end],
            "response_offsets": [response.start, response.end], "request_sha256": request.raw_sha256,
            "response_sha256": response.raw_sha256} for cid, request, response, _, _ in exchanges]})
    return auth[3][0], resource[4][1]


def validate_c01(directory: Path, *, admission: Admission) -> dict:
    """Read an ended run, returning JSON-safe diagnostics. No output files written."""
    result = {"scope": SCOPE, "raw_qualified": False, "status": "INDETERMINATE",
              "diagnostics": {}, "reasons": [], "boundaries": list(BOUNDARIES)}
    d = result["diagnostics"]
    try:
        validate_admission(admission)
        directory = Path(directory).absolute()
        initial_files = check_manifest(directory)
        # Authenticate the locally supplied public file BEFORE examining claims.
        public = read_regular(directory / "public/as-signing-public.pem", 65536)
        need(sha(public) == admission.public_key_pem_sha256, "external public-key hash mismatch")
        d["external_public_key_hash_matched_before_claims"] = True
        run = record(directory / "RESULT.json")
        need(run.get("scope") == SCOPE and run.get("status") == "SMOKE_CAPTURED_REQUIRES_INDEPENDENT_VALIDATION"
             and run.get("errors") == [], "runner did not close as a clean capture candidate")
        need(same_json(run.get("final_ports"), {"ports": [8081, 8082], "available_at_check": True}), "runner port cleanup record missing")
        need(read_regular(directory / "client/unwrap-input.json", 8192) == admission.client_input,
             "actual saved client input mismatch")
        processes = process_records(directory, run, admission)
        tcp = validate_relay_directory(directory / "tcp-capture", expected_transport="tcp",
            expected_listen=("127.0.0.1", 8081), expected_upstream=("127.0.0.1", 8082))
        rpc = validate_relay_directory(directory / "rpc-capture", expected_transport="unix_cdh_rpc",
            expected_listen=admission.unix_front, expected_upstream=admission.unix_back)
        d["relay_sessions"] = {"tcp": {"qualified": tcp.qualified, "reasons": list(tcp.reasons)},
                               "rpc": {"qualified": rpc.qualified, "reasons": list(rpc.reasons)}}
        need(tcp.qualified and rpc.qualified, "both whole relay sessions must qualify")
        for subdir, relay, owners in (("tcp-capture", tcp, ("kbs", "aa", "cdh")),
                                     ("rpc-capture", rpc, ("cdh", "client"))):
            for conn in relay.connections:
                end = record(directory / subdir / conn.connection_id / "END.json")
                # Services may exit before an existing connection's EOF is captured;
                # require connection establishment during their admitted lifetime.
                for owner in owners:
                    p = processes[owner]
                    need(p["started_unix_ns"] <= end["started_unix_ns"] <= p["ended_unix_ns"],
                         "capture connection outside owner lifetime")
        first_http, last_http = http_profile(directory / "tcp-capture", tcp, public, admission, d)
        need(len(rpc.connections) == 1, "C01 exactly one RPC connection required")
        conn = rpc.connections[0]
        actual = decode_unwrap_exchange(conn.client_to_upstream, conn.upstream_to_client,
                                        expected_request_input=admission.client_input)
        req_span = capture_span(directory / "rpc-capture", conn.connection_id, "client_to_upstream", 0, len(conn.client_to_upstream))
        res_span = capture_span(directory / "rpc-capture", conn.connection_id, "upstream_to_client", 0, len(conn.upstream_to_client))
        need(req_span[1] <= first_http <= last_http <= res_span[0], "HTTP chain not temporally enclosed by actual RPC")
        d["rpc_status_code"] = actual.status_code
        need(actual.status_code == 0 and actual.response_json is not None, "not a C01 successful RPC; no negative effect inferred")
        client = processes["client"]
        native = decode_native_capture(operation_id="C01-host-validation",
            stdout=read_regular(directory / "processes/client/stdout.bin"),
            stderr=read_regular(directory / "processes/client/stderr.bin"),
            returncode=client["returncode"], process_closed=client["process_closed"], capture_complete=client["capture_complete"])
        need(native.successful_output is True and native.reply_json == actual.response_json
             and not native.rpc_error_candidate, "RPC/CLI raw reply mismatch or contradictory output")
        d.update({"native_output_length": len(native.output_bytes), "native_output_sha256": sha(native.output_bytes),
                  "rpc_response_sha256": actual.response_sha256, "rpc_cli_reply_bytes_equal": True,
                  "reference_lek_sha256": sha(admission.reference_lek),
                  "reference_lek_bytes_equal": native.output_bytes == admission.reference_lek,
                  "source_anchors": {label: entry[1] for label, entry in admission.source_files.items()},
                  "binary_anchors": admission.binary_sha256, "origin_note": admission.origin_note})
        need(check_manifest(directory) == initial_files, "run changed during validation")
        result["raw_qualified"] = True
        result["status"] = "RAW_QUALIFIED_C01_CANDIDATE" if d["reference_lek_bytes_equal"] else "RAW_QUALIFIED_OUTPUT_MISMATCH"
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError) as exc:
        result["reasons"].append({"type": type(exc).__name__, "message": str(exc)})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--admission", type=Path, required=True,
                        help="external host JSON: binary_sha256, source_files{label:{path,sha256}}, client_input_path, reference_lek_path, public_key_pem_sha256, expected_issuer, unix_front/back, trusted_local_origin, stable_local_clocks, origin_note")
    args = parser.parse_args()
    try:
        obj = record(args.admission)
        obj["source_files"] = {k: (Path(v["path"]), v["sha256"]) for k, v in obj["source_files"].items()}
        obj["client_input"] = read_regular(Path(obj.pop("client_input_path")), 8192)
        obj["reference_lek"] = read_regular(Path(obj.pop("reference_lek_path")), 32)
        result = validate_c01(args.run_dir, admission=Admission(**obj))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {"scope": SCOPE, "raw_qualified": False, "status": "INDETERMINATE",
                  "reasons": [{"type": type(exc).__name__, "message": str(exc)}], "boundaries": BOUNDARIES}
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0 if result["raw_qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
