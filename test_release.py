#!/usr/bin/env python3
"""Bounded release regression checks; no native service or new observation."""
from __future__ import annotations
import base64
from contextlib import redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import verify
from release_inventory import retained_payload
from research_v7_20260908.controls.http_chain import collect_exchanges, qualify_chain, signed_interval
from research_v7_20260908.wire.ear_claims import EarEvidenceError
from research_v7_20260908.wire.relay_evidence import validate_relay_directory

ROOT = Path(__file__).resolve().parent


def cold_exchanges(case):
    root = ROOT / "data/cold" / case / "capture"
    tcp = validate_relay_directory(root / "tcp-capture", expected_transport="tcp",
        expected_listen=("127.0.0.1", 8081), expected_upstream=("127.0.0.1", 8082))
    assert tcp.qualified
    clocks = {row["event_sha256"]: row
              for line in (root/"CLOCK_EVENTS.jsonl").read_bytes().splitlines()
              if (row := json.loads(line))}
    return root, collect_exchanges(root/"tcp-capture", tcp, clocks)


class ReleaseChecks(unittest.TestCase):
    def test_01_complete_offline_replay(self):
        output = io.StringIO()
        with redirect_stdout(output):
            verify.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["new_native_calls"], 0)
        self.assertEqual(result["capture_subsets_requalified"], 6)
        self.assertEqual(result["comparator"]["original_method_API_calls"], 28)

    def test_02_closed_inventory_rejects_changes(self):
        # Each mutation is made only to a fresh temporary copy.
        for mutation in ("changed", "missing", "added", "symlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="attestflow-negative-") as tmp:
                target = Path(tmp)/"copy"
                shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git", "__pycache__"))
                path = target/"data/cold/C01/capture/client/unwrap-input.json"
                if mutation == "changed": path.write_bytes(path.read_bytes()+b" ")
                elif mutation == "missing": path.unlink()
                elif mutation == "added": (target/"undeclared.txt").write_text("unexpected")
                else: (target/"unexpected-link").symlink_to(path)
                old = verify.ROOT
                try:
                    verify.ROOT = target
                    with self.assertRaises(ValueError): verify.inventory()
                finally:
                    verify.ROOT = old

    def test_03_corrupt_signature_rejected(self):
        root, exchanges = cold_exchanges("C02")
        attest = next(e for e in exchanges if e.request.target == "/kbs/v0/attest")
        token = json.loads(attest.response.body)["token"].encode()
        key = (root/"public/as-signing-public.pem").read_bytes()
        signed_interval(token, key, "CoCo-Attestation-Service", *attest.response_wall)
        parts = token.split(b".")
        sig = bytearray(base64.urlsafe_b64decode(parts[2]+b"="*(-len(parts[2])%4)))
        sig[0] ^= 1
        parts[2] = base64.urlsafe_b64encode(sig).rstrip(b"=")
        with self.assertRaisesRegex(EarEvidenceError, "signature verification failed"):
            signed_interval(b".".join(parts), key, "CoCo-Attestation-Service", *attest.response_wall)

    def test_04_unused_refresh_not_selected_by_get(self):
        root, exchanges = cold_exchanges("C02")
        key = (root/"public/as-signing-public.pem").read_bytes()
        args = dict(resource_api="/kbs/v0/resource/default/attestflow-v7/kek-a",
                    public_key=key, issuer="CoCo-Attestation-Service")
        baseline = qualify_chain(exchanges, **args)
        self.assertEqual(baseline["all_get_count"], 3)
        self.assertEqual(len(baseline["handshakes"]), 4)
        self.assertFalse(baseline["handshakes"][-1]["used_by_resource_get"])
        unused = json.loads(exchanges[-1].response.body)["token"].encode()
        altered = list(exchanges)
        i = next(i for i,e in enumerate(altered) if e.request.method == "GET")
        altered[i] = replace(altered[i], request=replace(altered[i].request,
            authorization=b"Bearer "+unused, bearer_token=unused))
        with self.assertRaisesRegex(ValueError, "does not select exact current handshake"):
            qualify_chain(altered, **args)

    def test_05_only_fixed_signing_key_omission(self):
        root = ROOT/"data/cold/C01/capture"
        manifest = json.loads((root/"MANIFEST.json").read_bytes())
        expected = retained_payload(root, manifest)
        self.assertNotIn("private/as-signing-key.pem", expected)
        self.assertEqual(set(manifest["payload_sha256"])-set(expected), {"private/as-signing-key.pem"})
        with tempfile.TemporaryDirectory(prefix="attestflow-manifest-negative-") as tmp:
            clone = Path(tmp)/"C01/capture"
            clone.mkdir(parents=True)
            changed = dict(manifest)
            changed["payload_sha256"] = dict(manifest["payload_sha256"])
            del changed["payload_sha256"][next(iter(expected))]
            (clone/"MANIFEST.json").write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError,"original capture manifest pin"):
                retained_payload(clone,changed)

if __name__ == "__main__":
    unittest.main(verbosity=2)
