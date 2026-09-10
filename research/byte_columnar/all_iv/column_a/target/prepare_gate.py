#!/usr/bin/env python3
"""Freeze reviewed column-A artifacts; never parse or evaluate the target."""
import json
from pathlib import Path
import subprocess
import sys
import run_target as driver

EXPECTED = {
 "core.py": "1deda1788e9d9a49140325c7e0f7ce3eb53aa7d05e8e44590be4076da0bae472",
 "controls.py": "7887aef9fe4d82d762543575856cf3d2245700c9a0a64efa6bd21301ceefab18",
 "controls.json": "2fb68eff8b80fb120ca972a29ead64268f03057c10c00156fd49152e0cf62bea",
 "compat_source/build_compat.py": "6c0ab4888febcf87d45515bd4ad8b34f11a85edb05d0cb99ad1f75b8dd24f0aa",
 "compat_source/blowfish-compat.c": "3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad",
 "compat_source/blowfish.h": "bb4a14ecbd5dc92105b290d9261ed562a980c6e42b0d9b4b56e62b4b6c39665b",
 "compat_source/libdefs.h": "cdffb7ef7bc27b6eea90b73174077c377d8260ffd111fb8de3c2bbc938e28a31",
 "compat_source/mcrypt_modules.h": "2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
 "native/native.cpp": "960cdbaf643ca531728e2c6eeb337a5834842de9773c3a256319e9720bef1b07",
 "native/native_controls.py": "a86afa2cb63c42e2304aae9750d8017e14ee558a9d2c1f2f7011c26ec9b69540",
 "native/native_controls.json": "7b29daceb19899a6de3ad21954a0793513d324064c0bb169f66683f248ce5fb3",
 "native/native_search": "4ad339f8f5d88766317ef2b939c51d21628018635246bbaac45df8ed1b0218d4",
}
DRIVER_SHA = "de193398bb315e2315ace0e2538711d32a9e3543023a6ecf1fbbce9b9a61c7de"

def main():
 if driver.GATE.exists():
  raise SystemExit("refusing existing gate: " + str(driver.GATE))
 assert set(EXPECTED) == set(driver.REQUIRED)
 assert driver.sha(Path(driver.__file__)) == DRIVER_SHA
 for relative, expected in EXPECTED.items():
  assert driver.sha(driver.COLUMN / relative) == expected, relative
 assert driver.sha(driver.MDX) == driver.MDX_SHA
 for script in (driver.COLUMN / "controls.py", driver.COLUMN / "native/native_controls.py"):
  subprocess.run([sys.executable, "-B", str(script)], check=True, capture_output=True, text=True)
 native = json.loads((driver.COLUMN / "native/native_controls.json").read_text())
 assert native["build"]["local_binary_sha256"] == EXPECTED["native/native_search"]
 assert native["build"]["native_source_sha256"] == EXPECTED["native/native.cpp"]
 assert native["build"]["native_controls_source_sha256"] == EXPECTED["native/native_controls.py"]
 gate = {"identity": "ASTRA", "target_evaluated": False, "scope": driver.scope(),
  "artifact_hashes": EXPECTED, "driver_sha256": DRIVER_SHA,
  "prepare_gate_sha256": driver.sha(Path(__file__)), "mdx_sha256": driver.MDX_SHA,
  "canonical_text_sha256": driver.TEXT_SHA,
  "review": "Root and independent worker reviewed the prefix proof, native search, controls and target driver before this gate; no target evaluation during preparation.",
  "binary_note": "Hash binds the tested local executable. Portable source and build commands are published; this machine-specific binary is not published."}
 with driver.GATE.open("x") as handle:
  json.dump(gate, handle, indent=2, sort_keys=True)
  handle.write("\n")
 print(json.dumps({"identity":"ASTRA", "target_evaluated":False, "gate_sha256":driver.sha(driver.GATE), "driver_sha256":DRIVER_SHA, "cases":24}, indent=2))

if __name__ == "__main__":
 main()
