# Evidence and Oracle Semantics for Testing Attestation-Based Applications

Bounded replication artifact for the paper by **Songbo Bu**, Stevens Institute of Technology (contact: bluedog@ieee.org).

This repository provides offline inspection of selected recorded evidence and deterministic analysis replay. Running it launches no native service, container, TEE, scanner, or network client. It does not rerun the native experiments.

## Quick start

Use Python **3.11 or later**. Install the two pinned dependencies in your preferred isolated environment, then run:

```sh
python3 -m pip install -r requirements.txt
python3 -B verify.py
python3 -B test_release.py
```

Dependency installation is a separate network operation; `verify.py` does not install anything and its Python audit hook rejects subprocess launches, socket connections and socket binds. To save its JSON receipt, redirect stdout to a file **outside** this repository, so the closed payload inventory stays unchanged. Git's `.git/` transport metadata is excluded from the payload inventory; every other unlisted file is rejected. The main entry point works from any directory.

Expected verification: `status=PASS`, **six published capture subsets** checked, **zero new native calls**, 16 complete and nine partial Boolean cases, 24 observation projections, determinate counts **0/4/4/6** for J0/J1/J2/J3, and 28 original analysis API calls over 12 recorded and two transformed inputs. Q07 yields **FAIL/PASS**; restoring its missing edge yields **PASS/PASS**; adding a synthetic effect yields **FAIL/FAIL**.

`test_release.py` additionally checks rejection of changed, missing, added and symlink payloads, a corrupt JWT signature, selection of an unused refresh token by a GET, and any omission outside the fixed six-key list. These are software regression checks, not extra native observations.

## What this artifact establishes

| Claim | Evidence / executable check | Boundary |
|---|---|---|
| C01–C06 have the reported appraisal/output states | Original distributed TCP/RPC/configuration/process bytes, original public-key pins, and a derived omission-aware qualifier | Honest recorded origin and local clocks remain assumptions; the native executables and source-to-binary chain are not rebuilt |
| The direct three-valued rule agrees with state enumeration for the selected prohibition | Original functions on 16 complete and nine partial cases; 24 projections linked to rechecked native facts | Logical cases and projections are not independent native runs |
| Q07's split is a graph-requirement/branch-order difference | Original A_FULL and B3_TRACE on Q00–Q11 and two disclosed Q07 transformations | API analysis; no additional native effect and no uniform method-superiority claim |
| Earlier contrary results are preserved | Integrity checks on original failed-superiority, tied-native-comparison and failed-first-policy-sequence summaries | These are summary checks; their full raw records are outside this bounded release |
| The abstract observation condition has mechanized source | Two byte-identical Lean 4 core source files | Python verification does not execute Lean, and the theorem is not a concrete-system refinement proof |

The six native control states are:

| Case | c | R | Phi = not(c and R) | Meaning |
|---|---:|---:|---|---|
| C01 | 0 | 1 | true | Reference plaintext returned |
| C02 | 1 | 0 | true | Policy refusal and completed RPC error; three GETs, four handshakes |
| C03 | 1 | 1 | false | Deliberately permissive policy |
| C04 | 0 | 0 | true | Changed authentication tag; decryption error |
| C05 | 0 | 0 | true | Different-key resource alias; decryption error |
| C06 | 0 | 1 | true | Same-key resource alias; reference plaintext returned |

C01 and C04 are independent calls with their own generated input material. Their equal HTTP status does not imply equal raw traces or an opposite-property pair.

## Public release and sensitive-fixture handling

The original local inspection bundle included six locally generated P-256 signing **private** keys solely to satisfy its full capture manifests. They are **not distributed here**. All original capture manifests remain byte-identical, and `RELEASE_OMISSIONS.json` records exactly six omitted paths and their original SHA-256 values. `code/release_inventory.py` pins each original manifest and each omitted digest. The two published qualifier modules are derived only at their inventory comparison: they require every other original file with its original digest and reject additions. Their JWT signature, issuer, timing, request/token association, RPC closure and decryption checks are retained.

Consequently, this is verification of an explicitly published **capture subset**, not complete verification of the original manifests. Neither the omitted private-key contents nor their original private/public agreement are independently re-established by this release.

The included local bearer tokens are expired fixture tokens from loopback-only test services. The dummy KEKs and expected plaintext keys are intentional public fixture data used for offline cryptographic comparison; never deploy them or configure a service to trust them. No production credentials, personal home paths or native signing private-key material is included.

## Files and provenance

- `data/cold/C01`–`C06`: selected capture trees, original qualifications and origin declarations, and admitted dummy references.
- `data/model`: Boolean cases and native observation projections.
- `data/comparator`: the twelve original paired API cases and results.
- `data/limitations`: selected original negative/tied summaries.
- `code`: selected author implementation sources and schema; source-only service helpers may be imported, but `verify.py` is the supported offline entry point.
- `formal/`: the two abstract Lean files cited in Supporting Information S1. Optional commands are in `formal/README.md`.
- `ADMISSION.json`: a derived relative-path map and public checking-source pins. Native source/binary hashes describe the original declared admission; their binaries/build chain are not supplied.
- `PROVENANCE.json`: distinguishes byte-identical copies from public-release adaptations using project-relative paths and SHA-256 values.
- `MANIFEST.json`: closed public payload inventory, excluding itself and `.git/`. Hashes detect consistency changes; they are not independent timestamps or proof of honest capture.

## Scope not included

This release does not rebuild Trustee/guest-components, launch native controls, execute the complete 112-row historical comparison or 135-row model, replay all native-backed consumer/policy-transition/Linux-rebuild records, or run the signed sink experiment. It does not establish hardware-backed attestation, an adversarial-host guarantee, field behavior or independent-team replication. Full experiment denominators and limitations remain in the paper and Supporting Information.

## Dependencies and rights

No third-party package source or native binary is vendored. Python dependencies are `cryptography` (Apache-2.0 OR BSD-3-Clause) and `jsonschema` (MIT); their dependencies retain their respective upstream licenses. The Lean checker is an optional external tool, not bundled. The author-owned software and associated documentation are distributed under the MIT License in `LICENSE`, as authorized by Songbo Bu. Dependency licenses remain unchanged. The recorded dummy fixture data accompany the offline verification and must not be used as production keys or trust material.
