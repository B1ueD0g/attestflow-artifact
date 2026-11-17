"""Host-only observed facts for one closed native control capture.

No case id or predicted outcome is accepted. A qualified RPC error supports only
this synchronous return boundary, not absence of leakage through other outlets.
"""
from dataclasses import dataclass
import base64
import json
from pathlib import Path, PurePosixPath

from ..smoke.validate_c01 import (
    Admission, validate_admission, inventory, read_regular, record, need,
    same_json, sha, capture_span, NotQualified,
)
from ..smoke.c01_smoke import configuration_texts, sanitized_env, CHECK_CONTRA, EAR_RV
from ..wire.relay_evidence import validate_relay_directory
from ..wire.ttrpc_capture import decode_unwrap_exchange
from ..runtime.native_output import decode_native_capture, strict_json, standard_base64
from ..runtime.facts import (
    QualifiedRpcError, output_fact, evaluate_phi_output, check_gcm_reference,
    evaluate_gcm_correctness, ReferenceKind,
)
from .http_chain import collect_exchanges, qualify_chain

SCOPE = "DEVELOPMENT_CONTROL_CAPTURE"
CAPTURED = "CONTROL_CAPTURED_REQUIRES_INDEPENDENT_VALIDATION"
ALLOW_ALL = b"\n    package policy\n    allow = true\n"
RESOURCE_A = "kbs:///default/attestflow-v7/kek-a"
RESOURCE_B = "kbs:///default/attestflow-v7/kek-b"


@dataclass(frozen=True)
class ControlAdmission:
    origin: Admission
    native_output_dir: str
    rv_svn: str
    active_policy: str
    resource_keks: dict[str, bytes]


def checked_manifest(root):
    files = inventory(root)
    manifest = record(root / "MANIFEST.json")
    from release_inventory import retained_payload
    need(manifest.get("scope") == SCOPE and retained_payload(root, manifest) ==
         {name: value for name, value in files.items() if name != "MANIFEST.json"},
         "control manifest/scope/full inventory mismatch")
    return files


def validate_origin(a):
    need(isinstance(a, ControlAdmission), "explicit ControlAdmission required")
    validate_admission(a.origin)
    path = PurePosixPath(a.native_output_dir)
    need(path.is_absolute() and str(path) == a.native_output_dir and ".." not in path.parts
         and path.parent == PurePosixPath("/app/output"), "unadmitted native output directory")
    need(a.rv_svn in ("1", "empty") and a.active_policy in ("check-contra", "allow-all"),
         "unadmitted explicit configuration intervention")
    need(type(a.resource_keks) is dict and set(a.resource_keks) in ({RESOURCE_A}, {RESOURCE_A, RESOURCE_B})
         and all(type(k) is bytes and len(k) == 32 for k in a.resource_keks.values()), "explicit one/two dummy KEKs required")
    obj = strict_json(a.origin.client_input)
    need(type(obj) is dict and set(obj) == {"op", "keywrapparams", "keyunwrapparams"}
         and obj["op"] == "keyunwrap" and obj["keywrapparams"] == {"ec": None, "optsdata": None},
         "normal public unwrap request required")
    params = obj["keyunwrapparams"]
    need(type(params) is dict and set(params) == {"dc", "annotation"} and params["dc"] is None
         and type(params["annotation"]) is str, "unsupported public unwrap parameters")
    annotation_raw = standard_base64(params["annotation"].encode("ascii"))
    annotation = strict_json(annotation_raw)
    ref = check_gcm_reference(annotation_json=annotation_raw, resources=a.resource_keks)
    need(ref.kind is not ReferenceKind.INVALID_INPUT, "external reference annotation outside supported shape")
    return annotation, ref


def process_records(root, result, admission):
    a, native_root = admission.origin, admission.native_output_dir
    binaries = record(root / "BINARIES.json")
    need(set(binaries) == set(a.binary_sha256), "binary inventory mismatch")
    for name, digest in a.binary_sha256.items():
        need(binaries[name]["sha256"] == digest and binaries[name]["path"] == "/app/bin/" + name,
             "native binary identity differs from external admission")
    expected_argv = {
        "kbs": ["/app/bin/kbs", "--config-file", native_root + "/config/kbs.toml"],
        "aa": ["/app/bin/ttrpc-aa", "--config-file", native_root + "/config/aa.toml", "--attestation_sock",
               "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"],
        "cdh": ["/app/bin/ttrpc-cdh", "-c", native_root + "/config/cdh.toml"],
        "client": ["/app/bin/ttrpc-cdh-tool", "--socket", "unix://" + a.unix_front,
                   "--timeout", "50", "unwrap-key", "--annotation-path", native_root + "/client/unwrap-input.json"],
    }
    need(set(result["processes"]) == set(expected_argv), "not exactly four native processes")
    out = {}
    for name, argv in expected_argv.items():
        directory = root / "processes" / name
        start, end, pid = (record(directory / f) for f in ("START.json", "END.json", "PROCESS.json"))
        need(same_json(end, result["processes"][name]), "process END/RESULT mismatch")
        for key in ("name", "argv", "env", "cwd", "started_unix_ns"):
            need(same_json(start[key], end[key]), "process START/END identity mismatch")
        need(end["name"] == name and end["argv"] == argv and end["cwd"] == native_root
             and same_json(end["env"], sanitized_env(name)), "actual native launch configuration not admitted")
        need(start.get("pid") is None and start.get("returncode") is None
             and start.get("process_closed") is False and start.get("capture_complete") is False,
             "unsupported process START state")
        need(type(end["pid"]) is int and end["pid"] > 0 and type(pid["pid"]) is int
             and pid["pid"] == end["pid"], "native PID association failed")
        need(all(type(v) is int for v in (end["started_unix_ns"], pid["observed_unix_ns"], end["ended_unix_ns"]))
             and 0 <= end["started_unix_ns"] <= pid["observed_unix_ns"] <= end["ended_unix_ns"],
             "process interval invalid")
        need(end["process_closed"] is True and end["capture_complete"] is True
             and end["timed_out"] is False and end["errors"] == [] and type(end["returncode"]) is int,
             "process incomplete, timed out or invalid")
        if name != "client":
            term = any(s.get("signal") == "SIGTERM" and s.get("reason") == "registered_child_cleanup"
                       for s in end["signals"])
            need(end["returncode"] == 0 or (name == "kbs" and end["returncode"] == -15 and term),
                 "abnormal service exit")
        else:
            need(end["returncode"] >= 0 and end["signals"] == [], "client signaled; not normal terminal RPC evidence")
        for label in ("stdout", "stderr"):
            raw, meta = read_regular(directory / (label + ".bin")), end["streams"][label]
            need(meta["eof"] is True and type(meta["bytes"]) is int and meta["bytes"] == len(raw)
                 and meta["sha256"] == sha(raw), "native stream hash/length/EOF failed")
        out[name] = end
    need(len({value["pid"] for value in out.values()}) == 4, "native PID reuse is outside this profile")
    return out


def configuration_and_provisioning(root, a, processes):
    native = Path(a.native_output_dir)
    for name, value in configuration_texts(native, Path(a.origin.unix_back).parent).items():
        need(read_regular(root / "config" / name) == value.encode(), "actual config differs from frozen native configuration")
    policy = CHECK_CONTRA if a.active_policy == "check-contra" else ALLOW_ALL
    rv = {"svn": ["1"] if a.rv_svn == "1" else [], "launch_digest": ["abcde"],
          "major_version": 1, "minimum_minor_version": 1}
    for name, value in (("active-resource-policy.rego", policy), ("reference-checkContra.rego", CHECK_CONTRA),
                        ("ear-reference-supported.rego", EAR_RV)):
        need(read_regular(root / "config" / name) == value, "policy bytes differ from external configuration")
    need(same_json(record(root / "config/reference-values.json"), rv), "actual RV file differs from external intervention")
    url = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    expected = {
        "resource-policy": ("/kbs/v0/resource-policy", {"policy": url(policy)}, "application/json"),
        "attestation-policy": ("/kbs/v0/attestation-policy", {"type": "rego", "policy_id": "default_cpu", "policy": url(EAR_RV)}, "application/json"),
        "reference-values": ("/kbs/v0/reference-value", None, "application/json"),
    }
    for uri, key in a.resource_keks.items():
        name = uri.rsplit("/", 1)[1]
        expected["dummy-" + name] = ("/kbs/v0/resource/default/attestflow-v7/" + name, key, "application/octet-stream")
    actual = {p.name for p in (root / "admin").iterdir()}
    ready = sorted(name for name in actual if name.startswith("ready-"))
    need(1 <= len(ready) <= 30 and ready == [f"ready-{i:03d}" for i in range(len(ready))]
         and actual == set(expected) | set(ready), "unexpected admin attempts or provisioning inventory")
    for name, (path, wanted, content_type) in expected.items():
        directory = root / "admin" / name
        request, response = record(directory / "REQUEST.json"), record(directory / "RESPONSE.json")
        body, reply = read_regular(directory / "request-body.bin"), read_regular(directory / "response-body.bin")
        need(request["method"] == "POST" and request["url"] == "http://127.0.0.1:8082" + path
             and request["content_type"] == content_type and request["body_sha256"] == sha(body), "actual admin request identity failed")
        need(response["method"] == "POST" and response["path"] == path
             and response["host"] == "127.0.0.1" and type(response["port"]) is int and response["port"] == 8082
             and response["request_body_sha256"] == sha(body) and response["response_body_sha256"] == sha(reply)
             and response["complete"] is True and type(response["response_status"]) is int
             and response["response_status"] == 200 and response["error"] is None, "native admin provisioning not successfully closed")
        need(type(request["sent_unix_ns"]) is int and type(response["received_unix_ns"]) is int
             and processes["kbs"]["started_unix_ns"] <= request["sent_unix_ns"] <= response["received_unix_ns"]
             <= processes["aa"]["started_unix_ns"], "provisioning not enclosed before AA start")
        if name == "reference-values":
            obj = strict_json(body)
            need(set(obj) == {"version", "type", "payload"} and obj["version"] == "0.1.0" and obj["type"] == "sample"
                 and same_json(strict_json(standard_base64(obj["payload"].encode("ascii"))), rv), "RV registration payload differs")
        elif type(wanted) is bytes:
            need(body == wanted, "actual provisioned KEK differs from independent fixture")
        else:
            need(same_json(strict_json(body), wanted), "actual admin policy payload differs")
    # Readiness is setup traffic directly to the admin listener, never counted as
    # a resource GET or proof of effect. The complete successful final probe is
    # checked; failed earlier attempts remain in the full manifest.
    last = record(root / "admin" / ready[-1] / "RESPONSE.json")
    need(last["complete"] is True and type(last["response_status"]) is int and last["response_status"] == 200,
         "no successful admin readiness probe")


def qualify_effect(root, rpc, processes, a):
    need(rpc.qualified and len(rpc.connections) == 1, "exactly one whole qualified RPC exchange required")
    conn = rpc.connections[0]
    actual = decode_unwrap_exchange(conn.client_to_upstream, conn.upstream_to_client,
                                    expected_request_input=a.origin.client_input)
    client = processes["client"]
    observation = decode_native_capture(operation_id="qualified-native-control",
        stdout=read_regular(root / "processes/client/stdout.bin"), stderr=read_regular(root / "processes/client/stderr.bin"),
        returncode=client["returncode"], process_closed=client["process_closed"], capture_complete=client["capture_complete"])
    if actual.status_code == 0:
        need(client["returncode"] == 0 and observation.successful_output is True
             and observation.reply_json == actual.response_json and not observation.rpc_error_candidate,
             "successful RPC/CLI bytes or exit disagree")
        returned = True
    else:
        need(client["returncode"] != 0 and observation.successful_output is not True,
             "terminal RPC error contradicts native output or exit")
        returned = output_fact(observation, rpc_error=QualifiedRpcError(
            operation_id="qualified-native-control", raw_response=conn.upstream_to_client,
            qualification_reference="complete same-stream UnWrapKey raw reply, original input and admitted native endpoint"))
        need(returned is False, "error status does not establish a complete empty-output CLI observation")
    req = capture_span(root / "rpc-capture", conn.connection_id, "client_to_upstream", 0, len(conn.client_to_upstream))
    res = capture_span(root / "rpc-capture", conn.connection_id, "upstream_to_client", 0, len(conn.upstream_to_client))
    return actual, observation, returned, req, res


def validate_control(root: Path, *, admission: ControlAdmission):
    result = {"scope": SCOPE, "status": "INDETERMINATE", "raw_qualified": False,
              "effect_qualified": False, "ear_qualified": False, "successful_output": None,
              "actual_contra": None, "phi_output": None, "psi_gcm_return_only": None,
              "native_cause": "UNKNOWN", "diagnostics": {}, "reasons": [],
              "boundary": "Local constructed control; trust in launch/recorder/clocks/source is explicit. No other outlet, root-resistant proof, external replication, vulnerability or method advantage."}
    initial = None
    try:
        root = Path(root).absolute()
        annotation, reference = validate_origin(admission)
        initial = checked_manifest(root)
        public = read_regular(root / "public/as-signing-public.pem", 65536)
        need(sha(public) == admission.origin.public_key_pem_sha256, "external signer pin mismatch before JWT inspection")
        run = record(root / "RESULT.json")
        need(run.get("scope") == SCOPE and run.get("status") == CAPTURED and run.get("errors") == []
             and same_json(run.get("final_ports"), {"ports": [8081, 8082], "available_at_check": True}),
             "runner did not close as a clean raw candidate")
        need(read_regular(root / "client/unwrap-input.json", 8192) == admission.origin.client_input, "saved client input differs")
        processes = process_records(root, run, admission)
        configuration_and_provisioning(root, admission, processes)
        rpc = validate_relay_directory(root / "rpc-capture", expected_transport="unix_cdh_rpc",
            expected_listen=admission.origin.unix_front, expected_upstream=admission.origin.unix_back)
        need(rpc.qualified, "whole RPC evidence failed: " + str(rpc.reasons))
        for conn in rpc.connections:
            start = record(root / "rpc-capture" / conn.connection_id / "START.json")["started_unix_ns"]
            need(all(processes[who]["started_unix_ns"] <= start <= processes[who]["ended_unix_ns"]
                     for who in ("cdh", "client")), "RPC starts outside native owner lifetime")
        actual, observation, returned, rpc_request, rpc_response = qualify_effect(root, rpc, processes, admission)
        result.update(effect_qualified=True, successful_output=returned,
            psi_gcm_return_only=evaluate_gcm_correctness(successful_output=returned,
                output_bytes=observation.output_bytes, reference=reference))
        result["diagnostics"].update(rpc_status_code=actual.status_code, rpc_status_message=actual.status_message,
            output_sha256=None if observation.output_bytes is None else sha(observation.output_bytes),
            output_length=None if observation.output_bytes is None else len(observation.output_bytes),
            reference_lek_bytes_equal=None if observation.output_bytes is None else observation.output_bytes == admission.origin.reference_lek,
            reference_crypto_kind=reference.kind.value, rpc_request_sha256=actual.request_sha256,
            rpc_response_sha256=actual.response_sha256)
        tcp = validate_relay_directory(root / "tcp-capture", expected_transport="tcp",
            expected_listen=("127.0.0.1", 8081), expected_upstream=("127.0.0.1", 8082))
        need(tcp.qualified, "whole TCP evidence failed: " + str(tcp.reasons))
        for conn in tcp.connections:
            start = record(root / "tcp-capture" / conn.connection_id / "START.json")["started_unix_ns"]
            need(all(processes[who]["started_unix_ns"] <= start <= processes[who]["ended_unix_ns"]
                     for who in ("aa", "cdh", "kbs")), "TCP starts outside native owner lifetime")
        from ..collector.timed_tcp_relay import validate_event_clock
        streams = {c.connection_id: read_regular(root / "tcp-capture" / c.connection_id / "events.jsonl", 4 << 20)
                   for c in tcp.connections}
        clocks = validate_event_clock(root / "CLOCK_EVENTS.jsonl", event_streams=streams,
                                      stable_local_clocks=admission.origin.stable_local_clocks)
        need(clocks.qualified, "event-clock evidence not qualified: " + str(clocks.reasons))
        for cid, events in clocks.records_by_connection.items():
            connection = record(root / "tcp-capture" / cid / "END.json")
            need(all(connection["started_unix_ns"] <= event.wall_before_ns <= event.wall_after_ns
                     <= connection["ended_unix_ns"] for event in events),
                 "event wall bracket outside its recorded TCP connection lifetime")
        clock_map = {row["event_sha256"]: row for line in read_regular(root / "CLOCK_EVENTS.jsonl").splitlines()
                     if (row := strict_json(line))}
        exchanges = collect_exchanges(root / "tcp-capture", tcp, clock_map)
        chain = qualify_chain(exchanges, resource_api=annotation["kid"].replace("kbs:///", "/kbs/v0/resource/", 1),
                              public_key=public, issuer=admission.origin.expected_issuer)
        need(rpc_request[1] <= chain["first_http_monotonic_ns"] <= chain["last_http_monotonic_ns"] <= rpc_response[0],
             "all handshakes/GETs including final refresh are not enclosed by this RPC")
        result.update(ear_qualified=True, actual_contra=chain["actual_contra"])
        result["diagnostics"]["http_chain"] = chain
        if returned:
            result["native_cause"] = "SUCCESSFUL_RPC_RETURN"
        elif chain["all_gets_explicit_policy_deny"]:
            result["native_cause"] = "ALL_ACTUAL_GETS_POLICY_DENIED_THEN_COMPLETED_RPC_ERROR"
        elif chain["any_resource_http_200"] and actual.status_code == 13:
            logs = read_regular(root / "processes/cdh/stdout.bin") + read_regular(root / "processes/cdh/stderr.bin")
            marker = b"Caused by: decrypt LEK using KEK failed"
            if (actual.status_message == "[CDH] [ERROR]: Decrypt Image (UnwrapKey) failed"
                    and logs.count(marker) == 1 and reference.kind is ReferenceKind.AUTHENTICATION_FAILURE):
                result["native_cause"] = "NATIVE_DECRYPT_FAILURE_WITH_REFERENCE_AUTHENTICATION_FAILURE"
        need(checked_manifest(root) == initial, "capture changed during qualification")
        result.update(raw_qualified=True, status="RAW_QUALIFIED_CONTROL")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError) as exc:
        result["reasons"].append({"type": type(exc).__name__, "message": str(exc)})
    # A local return fact can be qualified while HTTP attribution is unknown.
    # It does not upgrade the whole control to known/correct or infer its cause.
    if initial is not None:
        try:
            need(checked_manifest(Path(root)) == initial, "capture changed during failed qualification")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            result.update(raw_qualified=False, status="INDETERMINATE", effect_qualified=False,
                          ear_qualified=False, successful_output=None, actual_contra=None,
                          psi_gcm_return_only=None, native_cause="UNKNOWN")
            result["reasons"].append({"type": type(exc).__name__, "message": str(exc)})
    result["phi_output"] = evaluate_phi_output(actual_contra=result["actual_contra"], successful_output=result["successful_output"])
    return result
