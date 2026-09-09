# ASTRA whole-number base-8/base-10 control gate

```json
{
  "identity": "ASTRA",
  "status": "target complete: 96 exact parser cells, zero complete parses",
  "scope": "Whole hexadecimal integer to base 8 or 10, four direct orientations, zero restoration 0..2, optional full digit reversal, fixed-3 and canonical variable-2/3 allowed-text endpoints"
}
```

The target operation order is: interpret one oriented hex string as an integer; render canonical base-8 or base-10 digits; optionally reverse those canonical digits; prepend 0, 1, or 2 restored zeros to the selected direction; then parse. The target has 48 labelled digit streams and two separate parser endpoints, for 96 parser cells.

Allowed plaintext bytes are TAB (9), LF (10), CR (13), and printable ASCII 32–126. Fixed-3 accepts padded tokens such as decimal `009` and octal `011`. Canonical variable parsing forbids leading zeros inside multi-digit tokens. Variable widths 2–3 are the target scope; widths 1–3 exist only as a control that demonstrates decimal TAB `9`.

Run the control gate from the repository root:

```sh
python3 -B research/rev7-20260909-codex/whole_numeric/controls.py --controls
```

The source refuses an existing control output. Target parsing is inaccessible without the explicit `--run-target` flag and a frozen `controls.json` whose source and input-file hashes match. No target command was run while preparing this gate.

The dynamic program returns exact counts and retains at most three paths. Short fixtures are independently enumerated recursively and compare both exact counts and complete path sets. Full-chain plants cover both bases and both target parsers, reconstruct the examined digits and oriented hex, and record leading-zero loss. The initial fixed-width TAB loses two zeros from decimal `009` and one from octal `011`, then recovers only under the matching restoration metadata. Separate reversed-direction plants cover decimal zero counts 0, 1, and 2 and octal counts 0 and 1. Octal with two restored zeros cannot reach either endpoint: fixed3 begins with a disallowed value 0–7, while canonical variable parsing forbids a leading-zero token.

Rejected local drafts are excluded from this published source snapshot.


## Recorded target result

The target ran once with the announced source and controls. `target_results.json` retains 96 exact parser cells over 48 distinct examined digit streams. No cell has a complete parse. Each base/parser combination has 24 cells and zero parses. This finite negative only covers the exact scope and operation order above; it is not an exclusion of arbitrary numeral conversions or later cipher layers.

Result SHA-256: `8c66657a8e2a0586b6496e36f776ccdbae08e206439ce6e8ca3c8f70564e2f60`.
