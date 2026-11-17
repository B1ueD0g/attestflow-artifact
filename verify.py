#!/usr/bin/env python3
"""Read retained wire evidence and re-run bounded analysis; no native services.

Only temporary internal ledgers are written outside this evidence directory.
The result is printed to stdout. No dependency download or network is attempted.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, replace
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT / "code" / "src"), str(ROOT / "code")]


def forbid_external_execution(event, args):
    if event in {"subprocess.Popen", "os.system", "socket.connect", "socket.bind"}:
        raise RuntimeError("offline review forbids: " + event)


sys.addaudithook(forbid_external_execution)


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_bytes())


def sha(path):
    require(stat.S_ISREG(path.lstat().st_mode), "not a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def inventory():
    manifest = read(ROOT / "MANIFEST.json")
    actual = {}
    for path in ROOT.rglob("*"):
        if path.relative_to(ROOT).parts[0] == ".git":
            continue  # Git transport metadata is not a distributed evidence payload.
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), "symlink/special file rejected")
        if path.is_file() and path != ROOT / "MANIFEST.json":
            actual[path.relative_to(ROOT).as_posix()] = sha(path)
    require(actual == manifest["payload_sha256"], "bundle inventory/hash mismatch")
    provenance = read(ROOT / "PROVENANCE.json")
    for relative, entry in provenance["copied_files"].items():
        require(actual[relative] == entry["sha256"], "copied bytes differ from source pin")
    return actual


def requalify_cold():
    from research_v7_20260908.smoke.validate_c01 import Admission
    from research_v7_20260908.controls.validate_control import ControlAdmission, validate_control

    config = read(ROOT / "ADMISSION.json")
    sources = {p: (ROOT / p, h) for p, h in config["frozen_source_sha256"].items()}
    rows = []
    for case in config["cases"]:
        cid = case["id"]
        directory = ROOT / "data/cold" / cid
        origin = read(directory / "ORIGIN.json")
        reference = read(directory / "reference.json")
        require(reference["dummy_only"] is True, "non-dummy reference forbidden")
        require(origin["interfaces"] == ["lo"] and origin["public_file_matches_private"] is True,
                "retained local-origin declaration differs")
        back = origin["cdh_config_socket"].removeprefix("unix://")
        admitted = Admission(
            binary_sha256=config["binary_sha256"],
            source_files={**sources, "separate-post-run-origin": (directory / "ORIGIN.json", sha(directory / "ORIGIN.json"))},
            client_input=(directory / "admitted-input.json").read_bytes(),
            reference_lek=base64.b64decode(reference["expected_lek_base64"], validate=True),
            public_key_pem_sha256=origin["public_pem_sha256_derived_from_configured_private"],
            expected_issuer=config["expected_issuer"],
            unix_front=str(Path(back).parent / "front.sock"), unix_back=back,
            trusted_local_origin=True, stable_local_clocks=True,
            origin_note="Retained author-controlled local capture and clocks are assumed honest. Relative-path review is not a rebuild or independent origin authentication.",
        )
        result = validate_control(directory / "capture", admission=ControlAdmission(
            origin=admitted, native_output_dir=case["native_output_dir"],
            rv_svn=case["rv_svn"], active_policy=case["active_policy"],
            resource_keks={uri: base64.b64decode(value, validate=True)
                           for uri, value in reference["resource_keks_base64"].items()},
        ))
        require(result["raw_qualified"] is True, cid + " raw qualification failed: " + str(result["reasons"]))
        require(result == read(directory / "QUALIFICATION.json"), cid + " recomputed qualification differs")
        chain = result["diagnostics"]["http_chain"]
        rows.append({"id": cid, "c": result["actual_contra"], "R": result["successful_output"],
                     "Phi": result["phi_output"], "cause": result["native_cause"],
                     "GETs": chain["all_get_count"], "handshakes": len(chain["handshakes"]),
                     "HTTP_exchanges": chain["http_exchange_count"],
                     "used_statuses": chain["actual_cpu_ear_statuses"],
                     "raw_qualification_identical": True})
    return rows


def check_model(native):
    from research_v7_20260908.controls.minimal_model import generic_compatibility, direct_strong_rule

    sizes = {}
    for filename, expected_size in (("CORE.json", 16), ("PARTIAL.json", 9)):
        rows = read(ROOT / "data/model" / filename)
        require(len(rows) == expected_size, "model denominator changed")
        for row in rows:
            a = generic_compatibility(dict(row["observation"]))
            b = direct_strong_rule(dict(row["observation"]))
            require(a["verdict"] == b["verdict"] == row["expected"], "finite model verdict differs")
            require(a == {k: v for k, v in row["generic"].items() if k != "status"}, "finite model compatible set differs")
        sizes[filename] = len(rows)
    known = {row["id"]: row for row in native}
    rows = read(ROOT / "data/model/PROJECTIONS.json")
    require(len(rows) == 24, "native projections denominator changed")
    coverage = {k: 0 for k in ("J0", "J1", "J2", "J3")}
    for row in rows:
        facts, obs, budget = known[row["case_id"]], row["observation"], row["budget"]
        require(obs["c"] is (facts["c"] if budget != "J0" else None), "projection c does not match requalified raw")
        require(obs["R"] is (facts["R"] if budget == "J3" else None), "projection R does not match requalified raw")
        require(generic_compatibility(dict(obs)) == row["generic"], "native model analysis differs")
        require(direct_strong_rule(dict(obs)) == row["direct"], "native baseline differs")
        require(row["generic"]["verdict"] == row["direct"]["verdict"], "unexpected method difference")
        coverage[budget] += row["direct"]["verdict"] != "UNKNOWN"
    require(list(coverage.values()) == [0, 4, 4, 6], "native determined counts differ")
    return {"complete_pairs": 16, "partial_pairs": 9, "native_projection_pairs": 24,
            "method_disagreements": 0, "determinate_by_budget": coverage}


def replay_comparators():
    from benchmarks.attestflow_synthetic.api import TrialInput, TraceEvent, EffectRecord, RunObservation, PairObservation
    from experiments.runtime.arms import AFullArm, B3TraceArm, CaseContext, inspect_evidence

    def load_run(raw):
        trial = TrialInput(**{**raw["trial"], "changed_fields": tuple(raw["trial"]["changed_fields"])})
        events = tuple(TraceEvent(**{**event, "predecessor_event_ids": tuple(event["predecessor_event_ids"])})
                       for event in raw["trace_events"])
        return RunObservation(trial, events, tuple(EffectRecord(**r) for r in raw["effect_records"]), raw["observer_available"])

    def run_pair(pair, contract):
        before = encoded(asdict(pair))
        context = CaseContext({}, {"decision_node": "application_gate"}, contract, {}, pair.positive.trial, pair.test.trial)
        health = inspect_evidence(contract, pair)
        a, b = AFullArm().analyze(context, pair), B3TraceArm().analyze(context, pair)
        require(before == encoded(asdict(pair)), "API mutated the shared input")
        return health, a, b

    output = []
    paths = sorted((ROOT / "data/comparator").glob("Q[0-9][0-9].json"))
    require(len(paths) == 12, "semantic inventory incomplete")
    for path in paths:
        raw = read(path)
        pair = PairObservation(load_run(raw["pair"]["positive"]), load_run(raw["pair"]["test"]))
        require(hashlib.sha256(encoded(asdict(pair))).hexdigest() == raw["pair_sha256"], "pair representation hash mismatch")
        health, a, b = run_pair(pair, raw["contract"])
        require(health.usable == raw["health_usable"], "shared admission differs")
        for name, result in (("A_FULL", a), ("B3_TRACE", b)):
            require(result.as_dict() == raw["arms"][name]["raw_diagnostic"]["result"], "original API result differs: " + path.stem + " " + name)
        output.append({"input": path.stem, "admitted": health.usable,
                       "raw_A_FULL": a.verdict, "raw_B3_TRACE": b.verdict})
        if path.stem == "Q07":
            q07, contract = pair, raw["contract"]
    by_node = {event.node_id: event for event in q07.test.trace_events}
    restored = replace(q07, test=replace(q07.test, trace_events=tuple(
        replace(event, predecessor_event_ids=(by_node["request_read"].event_id, *event.predecessor_event_ids))
        if event.node_id == "application_gate" else event for event in q07.test.trace_events)))
    synthetic = replace(q07.positive.effect_records[0], trial_id=by_node["request_read"].trial_id,
                        attempt_id=by_node["request_read"].attempt_id, request_id=q07.test.trial.request_id)
    added = replace(q07, test=replace(q07.test, effect_records=(synthetic,)))
    for name, pair, expected in (("Q07_edge_restored", restored, ("PASS", "PASS")),
                                 ("Q07_synthetic_effect_added", added, ("FAIL", "FAIL"))):
        health, a, b = run_pair(pair, contract)
        require(health.usable and (a.verdict, b.verdict) == expected, "derived Q07 explanation differs")
        output.append({"input": name, "admitted": True, "raw_A_FULL": a.verdict, "raw_B3_TRACE": b.verdict})
    return {"retained_pairs_replayed": 12, "derived_API_inputs": 2, "original_method_API_calls": 28,
            "rows": output, "boundary": "Raw diagnostic verdicts on rejected Q inputs are not accepted evidence verdicts; a rejected shared gate remains INDETERMINATE. API replay is not native execution."}


def main():
    before = inventory()
    native = requalify_cold()
    model = check_model(native)
    with tempfile.TemporaryDirectory(prefix="attestflow-review-") as scratch:
        old_temp = tempfile.tempdir
        try:
            tempfile.tempdir = scratch
            comparator = replay_comparators()
        finally:
            tempfile.tempdir = old_temp
    contrary = read(ROOT / "data/limitations/historical-superiority-gate.json")
    warm = read(ROOT / "data/limitations/warm-failed-original-summary.json")
    require(contrary["acceptance_gates"]["central_superiority_gate"] == "FAIL", "negative superiority gate absent")
    require(warm["status"] == "INCOMPLETE_RETAINED" and warm["qualified_sequences"] == 0,
            "original warm failure absent")
    require(before == inventory(), "bundle inputs changed during verification")
    result = {
        "status": "PASS", "release_status": "PUBLIC_REPLICATION_SUBSET",
        "scope": "PUBLISHED_CAPTURE_SUBSET_RECHECK_AND_BOUNDED_ANALYSIS_REPLAY",
        "runtime": {"python": platform.python_version(), "cryptography": version("cryptography"), "jsonschema": version("jsonschema")},
        "bundle_payload_count": len(before), "bundle_payload_bytes": sum((ROOT / p).stat().st_size for p in before),
        "new_native_calls": 0, "capture_subsets_requalified": 6, "omitted_fixture_signing_private_keys": 6,
        "native_rows": native, "finite_model": model, "comparator": comparator,
        "contrary_record_checks_only": {"historical_superiority_gate": "FAIL", "original_warm_batch": "INCOMPLETE_RETAINED"},
        "boundary": "Omission-aware release qualifier rereads unchanged distributed TCP/RPC bytes, verifies retained JWT signatures under admitted local public keys, rechecks timing/closure and dummy reference outputs. Exactly six signing private keys are omitted with pinned omission records; this is not complete verification of the original capture manifests. This does not verify native binaries, source-to-binary mapping, an adversarial host, external reproduction, mixed-history semantics or public availability. Supplement covers only the named subset; retained summary-only records do not substitute for raw replay.",
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
