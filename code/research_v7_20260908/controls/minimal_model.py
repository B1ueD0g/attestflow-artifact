"""Fixed Boolean observation audit; no native result or fixture inputs.

Method A enumerates the fixed compatible set; Method B applies an independent
direct rule. Shared input validation is an explicit common-mode dependency.
The runner records 16 core rows and 9 partial-knowledge rows separately. These
are logical implementation checks, never independent native samples.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import time


OMEGA = ((False, False), (False, True), (True, False), (True, True))
BUDGETS = ("J0", "J1", "J2", "J3")
TRUTH = {(False, False): True, (False, True): True, (True, False): True, (True, True): False}
# Independently transcribed nine-row contract, not computed by either method.
EXPECTED = {
    (False, False): "TRUE", (False, True): "TRUE", (False, None): "TRUE",
    (True, False): "TRUE", (True, True): "FALSE", (True, None): "UNKNOWN",
    (None, False): "TRUE", (None, True): "UNKNOWN", (None, None): "UNKNOWN",
}
DRAFT_SHA256 = "8b022e2cabcdf0b1a5182ca4c08055852cc6a038c655c3a82a9eb3e0a791c4fc"
PROTOCOL_SHA256 = "708612bc6ee9ee1d43665cd96ffe14a40e9f75da8b28d66dff6985e724d2d198"
CONTEXT = "opaque-fixed-application-context-v1"
KBS_BACKGROUND = "opaque-fixed-acquisition-background-v1"
BOUNDARY = ("Exhaustive fixed Boolean implementation audit; no native reachability, "
            "native trace equivalence, new algorithm, performance, external replication or superiority claim.")


class InvalidObservation(ValueError):
    pass


class EmptyCompatibility(ValueError):
    pass


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


_LOADED_SOURCE_SHA256 = _sha(Path(__file__).read_bytes())


def admit(observation):
    """Reject malformed/extra/out-of-budget facts; None alone means unknown.

    Opaque context/background may be retained but never constrain c or R.
    Expected verdicts, state IDs, fixture truth and case labels are not fields.
    """
    required = {"budget", "c", "R"}
    allowed = required | {"context", "kbs_background"}
    if type(observation) is not dict or not required <= set(observation) <= allowed:
        raise InvalidObservation("exact declared observation fields required; extra truth/label fields forbidden")
    budget, contra, returned = (observation[k] for k in ("budget", "c", "R"))
    if type(budget) is not str or budget not in BUDGETS:
        raise InvalidObservation("unknown observation budget")
    if any(value is not None and type(value) is not bool for value in (contra, returned)):
        raise InvalidObservation("c and R must be strict bool or None")
    if budget == "J0" and contra is not None:
        raise InvalidObservation("c is outside J0")
    if budget != "J3" and returned is not None:
        raise InvalidObservation("R is outside this budget")
    for key in ("context", "kbs_background"):
        value = observation.get(key)
        if value is not None and (type(value) is not str or len(value) > 4096):
            raise InvalidObservation("opaque context/background must be bounded string or None")
    if budget in ("J0", "J1") and observation.get("kbs_background") is not None:
        raise InvalidObservation("KBS observation is outside this budget")
    return budget, contra, returned


def _classify_compatible(states):
    if type(states) not in (tuple, list):
        raise InvalidObservation("a materialized compatible-state sequence is required")
    if not states:
        raise EmptyCompatibility("empty compatibility is structural failure, never vacuous TRUE")
    if any(type(state) is not tuple or len(state) != 2 or any(type(v) is not bool for v in state)
           for state in states):
        raise InvalidObservation("compatible states must be strict Boolean pairs")
    truth_values = {not (contra and returned) for contra, returned in states}
    verdict = "TRUE" if truth_values == {True} else "FALSE" if truth_values == {False} else "UNKNOWN"
    return {"verdict": verdict, "compatibility_size": len(states),
            "compatible_states": [{"c": c, "R": r} for c, r in states]}


def generic_compatibility(observation):
    _, contra, returned = admit(observation)
    compatible = tuple((c, r) for c, r in OMEGA
                       if (contra is None or c is contra) and (returned is None or r is returned))
    return _classify_compatible(compatible)


def direct_strong_rule(observation):
    # Intentionally does not call generic_compatibility, EXPECTED, TRUTH,
    # _classify_compatible, or a native/fixture helper.
    _, contra, returned = admit(observation)
    if contra is False or returned is False:
        verdict = "TRUE"
    elif contra is True and returned is True:
        verdict = "FALSE"
    else:
        verdict = "UNKNOWN"
    return {"verdict": verdict}


def projection(budget, contra, returned):
    if type(contra) is not bool or type(returned) is not bool:
        raise InvalidObservation("core projection requires two strict truth booleans")
    if type(budget) is not str or budget not in BUDGETS:
        raise InvalidObservation("unknown projection budget")
    return {"budget": budget, "c": contra if budget != "J0" else None,
            "R": returned if budget == "J3" else None, "context": CONTEXT,
            "kbs_background": KBS_BACKGROUND if budget in ("J2", "J3") else None}


def planned_rows():
    """A fixed ledger: truth labels are outside the methods' input objects."""
    for budget in BUDGETS:
        for index, (contra, returned) in enumerate(OMEGA, 1):
            observation = projection(budget, contra, returned)
            yield {"matrix": "CORE", "row_id": f"core-{budget}-{index:02d}",
                   "truth": {"c": contra, "R": returned, "phi_output": TRUTH[(contra, returned)]},
                   "observation": observation, "expected": EXPECTED[(observation["c"], observation["R"])]}
    for index, (contra, returned) in enumerate(((c, r) for c in (False, True, None)
                                               for r in (False, True, None)), 1):
        yield {"matrix": "PARTIAL", "row_id": f"partial-J3-{index:02d}", "truth": None,
               "observation": {"budget": "J3", "c": contra, "R": returned, "context": CONTEXT,
                               "kbs_background": KBS_BACKGROUND}, "expected": EXPECTED[(contra, returned)]}


def evaluate_row(plan):
    out = dict(plan)
    for name, method in (("generic", generic_compatibility), ("direct", direct_strong_rule)):
        try:
            # Each method gets its own shallow copy containing only admitted
            # scalar observations, not this row's truth/expected/matrix labels.
            value = method(dict(plan["observation"]))
            out[name] = {"status": "OK", **value}
        except Exception as exc:
            out[name] = {"status": "ERROR", "error": {"type": type(exc).__name__, "message": str(exc)}}
    both = all(out[name]["status"] == "OK" for name in ("generic", "direct"))
    out["disagreement"] = (out["generic"]["verdict"] != out["direct"]["verdict"]) if both else None
    out["status"] = "PASS" if both and all(out[n]["verdict"] == plan["expected"] for n in ("generic", "direct")) else "FAIL"
    return out


def summarize(rows):
    result = {}
    for matrix, expected_count in (("CORE", 16), ("PARTIAL", 9)):
        selected = [row for row in rows if row["matrix"] == matrix]
        group = {"planned_paired_rows": expected_count, "recorded_paired_rows": len(selected),
                 "failed_rows": sum(row["status"] != "PASS" for row in selected),
                 "completed_method_pairs": sum(row["disagreement"] is not None for row in selected),
                 "disagreements": sum(row["disagreement"] is True for row in selected), "by_budget": {}}
        for budget in BUDGETS:
            subset = [row for row in selected if row["observation"]["budget"] == budget]
            if not subset:
                continue
            counts = {}
            for name in ("generic", "direct"):
                values = [row[name].get("verdict") for row in subset]
                count = {v: values.count(v) for v in ("TRUE", "FALSE", "UNKNOWN")}
                count.update(errors=values.count(None), determinate=count["TRUE"] + count["FALSE"], denominator=len(subset))
                if matrix == "CORE":
                    count["incorrect_certain"] = sum(
                        row[name].get("verdict") in ("TRUE", "FALSE") and
                        (row[name]["verdict"] == "TRUE") != row["truth"]["phi_output"] for row in subset)
                counts[name] = count
            group["by_budget"][budget] = counts
        result[matrix] = group
    return result


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _write_new(path, raw):
    with path.open("xb") as stream:
        if stream.write(raw) != len(raw):
            raise OSError("short audit output write")
        stream.flush()
        os.fsync(stream.fileno())


def _source_snapshot():
    parent = Path(__file__).resolve().parent
    names = ("minimal_model.py", "MODEL_PROTOCOL_V1.md", "MODEL_BASELINE_DRAFT.md")
    result = {}
    for name in names:
        path = parent / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("source/protocol must be a regular local file")
        result[name] = path.read_bytes()
    if _sha(result["minimal_model.py"]) != _LOADED_SOURCE_SHA256:
        raise ValueError("loaded model source differs from current disk source")
    if _sha(result["MODEL_BASELINE_DRAFT.md"]) != DRAFT_SHA256:
        raise ValueError("accepted semantic draft digest changed")
    if _sha(result["MODEL_PROTOCOL_V1.md"]) != PROTOCOL_SHA256:
        raise ValueError("accepted semantic protocol digest changed")
    return result


def _csv_bytes(rows):
    output = io.StringIO(newline="")
    keys = ("matrix", "row_id", "truth", "observation", "expected", "generic", "direct", "disagreement", "status")
    writer = csv.DictWriter(output, fieldnames=keys, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: json.dumps(row[key], sort_keys=True, allow_nan=False) if type(row[key]) in (dict, bool) or row[key] is None else row[key]
                         for key in keys})
    return output.getvalue().encode()


def run_audit(output: Path, *, development=False):
    """Exclusive output; BEGIN/source snapshot precede all 25 evaluations.

    development=True exists for temporary unit tests, not a second methodology.
    Production use still needs the root's separate source/execution freeze.
    """
    if not isinstance(output, Path) or type(development) is not bool:
        raise TypeError("Path output and strict development bool required")
    output = output.absolute()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    rows, failures, sources = [], [], None
    scope = "DEVELOPMENT_UNIT_TEST" if development else "FIXED_BOOLEAN_MODEL_AUDIT"
    try:
        _write_new(output / "BEGIN.json", _json_bytes({"schema": "attestflow-v7-minimal-model-v1", "state": "STARTED_NOT_COMPLETE",
            "scope": scope, "started_unix_ns": time.time_ns(), "planned_core_rows": 16, "planned_partial_rows": 9,
            "python": sys.version, "platform": platform.platform(), "boundary": BOUNDARY}))
        sources = _source_snapshot()
        (output / "source_snapshot").mkdir()
        for name, raw in sources.items():
            _write_new(output / "source_snapshot" / name, raw)
        _write_new(output / "SOURCES.json", _json_bytes({"sha256": {n: _sha(raw) for n, raw in sources.items()},
            "loaded_source_sha256": _LOADED_SOURCE_SHA256, "semantic_draft_sha256": DRAFT_SHA256,
            "semantic_protocol_sha256": PROTOCOL_SHA256,
            "boundary": "This identity record is not external approval or independent build evidence."}))
        with (output / "rows.jsonl").open("xb") as ledger:
            for plan in planned_rows():
                row = evaluate_row(plan)
                raw = (json.dumps(row, sort_keys=True, allow_nan=False) + "\n").encode()
                if ledger.write(raw) != len(raw):
                    raise OSError("short row ledger write")
                ledger.flush()
                os.fsync(ledger.fileno())
                rows.append(row)
        for matrix in ("CORE", "PARTIAL"):
            selected = [row for row in rows if row["matrix"] == matrix]
            _write_new(output / f"{matrix}.json", _json_bytes(selected))
            _write_new(output / f"{matrix}.csv", _csv_bytes(selected))
        if _source_snapshot() != sources:
            raise ValueError("source/protocol changed while audit was running")
    except BaseException as exc:
        failures.append({"type": type(exc).__name__, "message": str(exc)})
    summary = summarize(rows)
    complete = (not failures and len(rows) == 25 and all(row["status"] == "PASS" for row in rows)
                and summary["CORE"]["recorded_paired_rows"] == 16 and summary["PARTIAL"]["recorded_paired_rows"] == 9)
    result = {"schema": "attestflow-v7-minimal-model-result-v1", "scope": scope,
              "status": "PASS" if complete else "FAILED_OR_INCOMPLETE", "summary": summary,
              "failures": failures, "failed_row_ids": [r["row_id"] for r in rows if r["status"] != "PASS"],
              "completed_unix_ns": time.time_ns(), "boundary": BOUNDARY}
    # If storage itself is unavailable these writes may fail. Existing BEGIN,
    # source snapshot and fsynced prefix remain; never erase/relabel partial data.
    _write_new(output / "RESULT.json", _json_bytes(result))
    files = {p.relative_to(output).as_posix(): _sha(p.read_bytes()) for p in sorted(output.rglob("*")) if p.is_file()}
    _write_new(output / "MANIFEST.json", _json_bytes({"scope": scope, "payload_sha256": files}))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--development", action="store_true", help="label an explicit development execution, never a formal result")
    args = parser.parse_args(argv)
    result = run_audit(args.output, development=args.development)
    print(json.dumps({"status": result["status"], "scope": result["scope"], "output": str(args.output.absolute())}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
