#!/usr/bin/env python3
"""Temporary reproducible build adapter for the frozen prefix13 native source."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent
CONTROL_SOURCE = NATIVE / "native_controls.py"
CONTROL_SOURCE_SHA = "901def5c5a4f329354611d9930f55b441619ae9fb2ff219aed0e560329b4221d"
NATIVE_SOURCE_SHA = "f9c731e222381597dcb03d00155549f12fb6d82923975b13f2a18d3c05e631d0"
EXPECTED_BINARY_SHA = "704f5f431b0b92136624eaba960605f2a652e8818a42b86a8a44e14566722b04"
EXPECTED_OBJECT_SHA = "022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(directory: Path):
    if sha(CONTROL_SOURCE) != CONTROL_SOURCE_SHA or sha(NATIVE / "native.cpp") != NATIVE_SOURCE_SHA:
        raise AssertionError("frozen native source drift")
    spec = importlib.util.spec_from_file_location("astra_prefix13_native_build_source", CONTROL_SOURCE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    binary, evidence = module.build_temporary(directory)
    if evidence["binary_sha256"] != EXPECTED_BINARY_SHA or evidence["object_sha256"] != EXPECTED_OBJECT_SHA:
        raise AssertionError(("host build differs from accepted controlled build", evidence))
    return {"binary": str(binary), **evidence}
