# Reproduce the Bifid SMT evidence

Identity: ASTRA. Rev7 remains unsolved.

The completed pilot and full-message follow-up exclude all 16 combinations of four registered orientations and periods 3, 31, 99, and 1091 under arbitrary one-square 4×4 Bifid and the broad 213-byte UTF-8 union. The pilot supplies seven UNSAT results at prefix 128; the follow-up supplies nine UNSAT results at full length 546. The prior six prefix-only SAT models fail the complete text checks and the three prior timeouts were unresolved. Their original ledgers remain unchanged.

The parent README and BAGMODE describe synthetic controls and their historical scope. `audit_controls.py` supplies the stronger independent audit: it reconstructs fixtures, enumerates all 24 reduced completions, checks all 256 byte predicates, and independently decodes and re-encrypts every saved SAT model. Initial Int-model timeouts remain incomplete, not negative results.

## Runtime

These measurements and exact native-library pins use Python 3.9.6 on macOS ARM64 with z3-solver 4.15.3.0 (Z3 runtime 4.15.3). `dependency/dependency.json` records the isolated pip download/install commands, wheel and library SHA-256 values, and official source tag. Download the pinned wheel into `dependency/`, verify its recorded SHA-256, then install it with `--no-deps --no-compile --target dependency/runtime`. The wheel is supplied by the original distributor rather than duplicated in this repository. Its license and package metadata are included. The native-library audit is specific to the recorded platform.

## Restore and verify

From this directory:

```sh
python3 -B restore_smt.py --restore
python3 -B audit_controls.py
python3 -B odd_pilot/verify_results.py
python3 -B odd_fullbag/verify_results.py
```

`restore_smt.py` verifies the frozen transport and reconstructs 27 artifacts: both parent SMT formulas and all 25 target formula gzip files. Existing exact files are checked; different existing files are refused. No solver is run by restoration. The target verifiers reconstruct every formula from the pinned canonical input and source without executing a second search. SAT plaintexts are independently decoded and re-encrypted. The controls audit makes small fixed/reduced synthetic checks; it does not rerun the historical unknown-square timeouts.

The full target source, gates, selected cell lists, per-cell statuses, timings, plaintext models where applicable, and report limits are retained in `odd_pilot/` and `odd_fullbag/`. The target run commands refuse existing outputs; use the verification commands to inspect these completed experiments.

The 213-byte union is a necessary byte-membership condition for UTF-8 with printable ASCII plus TAB/LF/CR as single-byte characters. Membership alone is not well-formed UTF-8. The diagnostic named `full_exact_endpoint` uses ASCII plus five specified punctuation characters, whereas the separate even-period invariant uses a 201-codepoint endpoint. No broader algorithm or untested period is excluded by the 16-cell SMT result.
