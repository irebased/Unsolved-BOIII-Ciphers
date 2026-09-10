#!/usr/bin/env python3
"""Create a reviewed hash-only prefix13 gate. Do not run before root review and preregistration."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED_DRIVER = "166edaadd98a95abfa6c6336652be4d2218491d548335f6714d048c7e491fa59"
EXPECTED_BUILD_HELPER = "1a4a5e8e5e18c382e259a82f1deef4d88dbde5489ea30bf75d36874e8cec81ee"
EXPECTED_DRIVER_CONTROLS_SOURCE = "feeed14799985557cf32ef63b063a65f94a0d8994d4845f51bf6a8faa7d3ba35"
EXPECTED_DRIVER_CONTROLS_LEDGER = "f86b6eb63765565849838e4ff0da843f34fa5e4a3e0bbab40813cdc32bfda487"
EXPECTED_README = "bf9a976dc60610e0bca5cd12a27f4d7e8176203c1b2eca1fa1e9f581dda03371"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert sha(HERE / "run_target.py") == EXPECTED_DRIVER
    assert sha(HERE / "build_native.py") == EXPECTED_BUILD_HELPER
    assert sha(HERE / "driver_controls.py") == EXPECTED_DRIVER_CONTROLS_SOURCE
    assert sha(HERE / "driver_controls.json") == EXPECTED_DRIVER_CONTROLS_LEDGER
    assert sha(HERE / "README.md") == EXPECTED_README
    spec = importlib.util.spec_from_file_location("astra_prefix13_registered_driver", HERE / "run_target.py")
    driver = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(driver)
    driver.require_artifacts()
    assert sha(driver.MDX) == driver.MDX_SHA
    controls = json.loads((HERE / "driver_controls.json").read_text())
    assert controls["identity"] == "ASTRA" and controls["target_evaluated"] is False
    assert controls["rev7_file_read"] is False and all(controls["assertions"].values())
    output = HERE / "target_gate.json"
    if output.exists():
        raise SystemExit("refusing existing gate")
    gate = {
        "identity": "ASTRA",
        "target_evaluated": False,
        "authorization": "FABLE preregistration plus separate root GO required",
        "scope": driver.scope(),
        "driver_sha256": EXPECTED_DRIVER,
        "build_helper_sha256": EXPECTED_BUILD_HELPER,
        "driver_controls_source_sha256": EXPECTED_DRIVER_CONTROLS_SOURCE,
        "driver_controls_ledger_sha256": EXPECTED_DRIVER_CONTROLS_LEDGER,
        "target_readme_sha256": EXPECTED_README,
        "gate_builder_sha256": sha(Path(__file__)),
        "artifact_hashes": driver.EXPECTED_ARTIFACTS,
        "expected_binary_sha256": driver.EXPECTED_BINARY_SHA,
        "expected_object_sha256": driver.EXPECTED_OBJECT_SHA,
        "mdx_sha256": driver.MDX_SHA,
        "canonical_text_sha256": driver.TEXT_SHA,
        "review_evidence": "Root reviewed the driver, build adapter, controls and gate builder. Root independently regenerated driver_controls.json byte for byte, SHA256 f86b6eb63765565849838e4ff0da843f34fa5e4a3e0bbab40813cdc32bfda487, including exact native binary/object hashes and all retained synthetic prefix replays. Gate creation itself hashes the MDX only and does not extract or evaluate target ciphertext.",
    }
    with output.open("x") as handle:
        json.dump(gate, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"identity": "ASTRA", "target_evaluated": False, "gate_sha256": sha(output), "driver_sha256": EXPECTED_DRIVER}))


if __name__ == "__main__":
    main()
