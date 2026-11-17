# Abstract Lean models

The two `.lean` files are byte-identical author sources cited in Supporting Information S1. They use Lean 4 core without Mathlib. With Lean 4 already installed, run:

```sh
lean formal/lean/TraceOnlyImpossibility.lean
lean formal/bridge_v4/BridgeV4.lean
```

The Python entry point does not execute Lean or install a toolchain. The model does not prove refinement of the concrete Python, Trustee or OS composition. This release does not include the native sink experiment or its complete conformance package.
