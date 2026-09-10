#!/usr/bin/env python3
"""Bind reviewed every-IV Blowfish sources without evaluating the target."""
import json
from pathlib import Path
import subprocess
import sys
import run_target as driver

FROZEN = {'artifact_hashes': {'research/byte_columnar/all_iv/column_a/compat_source/COPYING.LIB': 'ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532', 'research/byte_columnar/all_iv/column_a/compat_source/PROVENANCE.md': 'ffb5e443fa77844a31dbe84440c9cc452f2139a766e61b570602cbc4cfcaea3a', 'research/byte_columnar/all_iv/column_a/compat_source/blowfish-compat.c': '3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad', 'research/byte_columnar/all_iv/column_a/compat_source/blowfish.h': 'bb4a14ecbd5dc92105b290d9261ed562a980c6e42b0d9b4b56e62b4b6c39665b', 'research/byte_columnar/all_iv/column_a/compat_source/build_compat.py': '6c0ab4888febcf87d45515bd4ad8b34f11a85edb05d0cb99ad1f75b8dd24f0aa', 'research/byte_columnar/all_iv/column_a/compat_source/libdefs.h': 'cdffb7ef7bc27b6eea90b73174077c377d8260ffd111fb8de3c2bbc938e28a31', 'research/byte_columnar/all_iv/column_a/compat_source/mcrypt_modules.h': '2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180', 'research/rev7-20260909-codex/iv_independent/blowfish_solver/REPORT.md': '41cbdcd404f6bd8ee139a69e8f1e0b949cfeddbbf558ed9af5c62b6b9d583bfd', 'research/rev7-20260909-codex/iv_independent/blowfish_solver/controls.json': 'b03e5fe574da9206bdee8b0e1602cd854c3623dcefc9a70585971764f7d01346', 'research/rev7-20260909-codex/iv_independent/blowfish_solver/controls.py': '9866ccef1ada24246054ae4e179088c71af3b23d5032a0238c193ce318776592', 'research/rev7-20260909-codex/iv_independent/blowfish_solver/native': '23063a1f86329572d0b10a507804210f0743b60f78f65a8366afd9b4ef44583f', 'research/rev7-20260909-codex/iv_independent/blowfish_solver/native.cpp': 'b7f3a187f29705fc21f7a529b7722f9f9d936a4f66715e107ff52acfb11ca433', 'research/rev7-20260909-codex/iv_independent/blowfish_solver/native_build.json': 'ec211891fda2871ef9a27505728d53960aa51ffb4aaad4f7be972e07abd979c0', 'research/rev7-20260909-codex/iv_independent/blowfish_solver/target/README.md': 'd12d6051a7ca577228c073dc33c025e3ace0a2a137556ae42cc6ecacf8959625', 'research/rev7-20260909-codex/iv_independent/blowfish_solver/target/benchmark.json': 'd6283ad10e67839a4b083f350fdfa9d9f0f2947b4d240336fb491e56e0b08c47', 'research/rev7-20260909-codex/iv_independent/blowfish_solver/target/benchmark.py': '489d62c8401879b417ec54785ee0ee184388ad45a2aae46d37f64187e9e47b92'}, 'authorization': 'FABLE preregistered; root GO required', 'canonical_text_sha256': '5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c', 'driver_sha256': 'd9b6d343f23c8f343ce0584a20a659d5277d5f40385ec68821e7d1b7ce7e32d9', 'identity': 'ASTRA', 'mdx_sha256': '085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91', 'note': 'Frozen registered specification; target execution follows separate FABLE notice and root GO.', 'scope': {'cells': 8, 'certificate': '16! mapping weight only when native reports complete; capped cells retain uncovered weight', 'ciphers': ['blowfish', 'blowfish_compat'], 'compatibility_primitive': 'word_reverse(BF(word_reverse(block))) using reversal inside each 32-bit word', 'constraint': 'for i>=8, P_i=C_i XOR E_key(C[i-8:i])[0]', 'external_iv': 'arbitrary eight bytes; not recovered or searched', 'identity': 'ASTRA', 'key_hex': '5a6f6d62696573', 'mode': 'CFB8', 'node_limit_per_cell': 1000000000, 'order': 'default frozen greedy geometry order; no explicit override', 'orientations': ['forward', 'full_hex_reverse', 'byte_reverse', 'nibble_swap'], 'relaxed_window_bytes': {'additional_hex': ['80', '93', '94', '98', '99', 'a6', 'e2'], 'ascii': 'TAB LF CR and 32..126', 'count': 105}, 'search_semantics': 'fresh root per cell; caps are not additive', 'strict_suffix': {'initial_state_set': [0, 1, 2], 'terminal_state': 0, 'utf8': ['e28093', 'e28094', 'e28098', 'e28099', 'e280a6']}, 'survivors': 'retain exact mapping and suffix bytes; independently reconstruct, validate and re-encrypt under two arbitrary IVs', 'unknown_representation': 'global bijection of 16 displayed hex symbols to nibbles'}, 'target_evaluated': False}

def main():
 if driver.GATE.exists():
  raise SystemExit("refusing existing gate: " + str(driver.GATE))
 assert FROZEN["scope"] == driver.scope()
 assert FROZEN["driver_sha256"] == driver.sha(Path(driver.__file__))
 assert set(FROZEN["artifact_hashes"]) == set(driver.ARTIFACTS)
 for relative, expected in FROZEN["artifact_hashes"].items():
  assert driver.sha(driver.ROOT / relative) == expected, relative
 assert driver.sha(driver.MDX) == FROZEN["mdx_sha256"] == driver.MDX_SHA
 for script in (driver.PACKAGE / "controls.py", driver.HERE / "benchmark.py"):
  subprocess.run([sys.executable, "-B", str(script)], check=True, capture_output=True, text=True)
 gate = dict(FROZEN)
 gate["prepare_gate_sha256"] = driver.sha(Path(__file__))
 with driver.GATE.open("x") as handle:
  json.dump(gate, handle, indent=2, sort_keys=True)
  handle.write("\n")
 print(json.dumps({"identity":"ASTRA", "target_evaluated":False, "gate_sha256":driver.sha(driver.GATE), "driver_sha256":FROZEN["driver_sha256"], "cells":8}, indent=2))

if __name__ == "__main__":
 main()
