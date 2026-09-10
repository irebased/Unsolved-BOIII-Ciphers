#!/usr/bin/env python3
"""Reproducibly build the source-backed RC2 column-A executable."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
EXPECTED = {
    "native.cpp": "3c634ea5fa32caa146c2a078f85abdbc98984675744e7ffcf1977355e455a1cd",
    "source/rc2.c": "37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19",
    "source/rc2.h": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "source/COPYING.LIB": "ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
    "source_build/libdefs.h": "556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e",
    "source_build/mcrypt_modules.h": "2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def build(output_dir):
    for rel, expected in EXPECTED.items():
        assert sha(PACKAGE / rel) == expected, rel
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    obj = output_dir / "rc2.o"
    binary = output_dir / "native_search"
    if obj.exists() or binary.exists():
        raise RuntimeError("refusing existing build output")
    commands = [
        ["clang", "-O2", "-I" + str(PACKAGE / "source_build"),
         "-I" + str(PACKAGE / "source"), "-c", str(PACKAGE / "source/rc2.c"), "-o", str(obj)],
        ["clang++", "-std=c++17", "-O3", str(PACKAGE / "native.cpp"), str(obj), "-o", str(binary)],
    ]
    records = []
    for command in commands:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        records.append({"command": command, "stdout": completed.stdout, "stderr": completed.stderr})
    return {"identity": "ASTRA", "source_hashes": EXPECTED, "commands": records,
            "object_sha256": sha(obj), "binary_sha256": sha(binary), "binary": str(binary)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output_dir), indent=2))

if __name__ == "__main__":
    main()
