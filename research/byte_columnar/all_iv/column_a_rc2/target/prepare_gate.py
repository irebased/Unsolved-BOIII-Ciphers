#!/usr/bin/env python3
"""Create the reviewed RC2 column-A gate; only hash the target MDX."""
import hashlib, importlib.util, json
from pathlib import Path
HERE = Path(__file__).resolve().parent
EXPECTED_DRIVER = "deea54124124bae750ba57a35ebed6c5770e4f861ed25ae3aed6a7c660b1ab9a"
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    assert sha(HERE / "run_target.py") == EXPECTED_DRIVER
    spec = importlib.util.spec_from_file_location("rc2_registered_driver", HERE / "run_target.py")
    driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
    assert sha(driver.MDX) == driver.MDX_SHA
    for rel, expected in driver.REQUIRED.items():
        assert sha(driver.artifact_path(rel)) == expected, rel
    output = HERE / "target_gate.json"
    if output.exists(): raise SystemExit("refusing existing gate")
    gate = {
        "identity": "ASTRA", "target_evaluated": False,
        "authorization": "FABLE preregistration plus separate root GO required",
        "scope": driver.scope(), "driver_sha256": EXPECTED_DRIVER,
        "target_readme_sha256": sha(HERE / "README.md"),
        "build_helper_sha256": sha(HERE / "build_native.py"),
        "gate_builder_sha256": sha(Path(__file__)),
        "artifact_hashes": driver.REQUIRED,
        "expected_binary_sha256": driver.EXPECTED_BINARY_SHA,
        "expected_object_sha256": driver.EXPECTED_OBJECT_SHA,
        "mdx_sha256": driver.MDX_SHA, "canonical_text_sha256": driver.TEXT_SHA,
        "review_evidence": "Root reviewed native/control/target source, regenerated all synthetic controls with deterministic equality and reproduced the exact tested native binary hash; no target evaluation during preparation."
    }
    with output.open("x") as handle:
        json.dump(gate, handle, indent=2, sort_keys=True); handle.write("\n")
    print(json.dumps({"identity": "ASTRA", "target_evaluated": False, "gate_sha256": sha(output), "driver_sha256": EXPECTED_DRIVER}))
if __name__ == "__main__": main()
