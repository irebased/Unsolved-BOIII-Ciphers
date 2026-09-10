from __future__ import annotations

"""Synthetic source-backed Rijndael-256 CFB8 interval adapter and cascade composition."""

import ctypes
import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIMITIVE = HERE.parent / "rijndael256_controls"
CASCADE_RUNTIME = HERE.parent / "iv_independent/cascade/runtime"
CASCADE_INTERVAL = HERE.parent / "iv_independent/cascade"
BS = 32
KEYS = {
    "rijndael256_key16": b"Zombies" + b"\0" * 9,
    "rijndael256_key24": b"Zombies" + b"\0" * 17,
    "rijndael256_key32": b"Zombies" + b"\0" * 25,
}
TRANSFORMS = ("forward", "byte_reverse", "nibble_swap", "full_hex_reverse")
PINS = {
    "rijndael256_controls/controls.json": "2e164a7b6091f5a1c76a1863cd45ddb2c919597350ff20e3ce52c131ed9c804c",
    "rijndael256_controls/controls.py": "c35dde4e66b4a5633c0b0d14086bb1011ae313448d4e460ef405dd53d29f6cb2",
    "rijndael256_controls/build_source.py": "d32cac36412340865b2fd28d8b6437f9c2f508cd229c58881c3285d3e3039961",
    "rijndael256_controls/js_blocks.js": "ceefc2c2c15b7cb60b07ba14539c1ec99bda682409a728bc2fa04ee4df292f52",
    "rijndael256_controls/source/aes.js": "c8d6903ff7d6b090b2050f1c59dcf63ee08ac0c084caa11f9912bf5b20f90a8a",
    "rijndael256_controls/source/rijndael-256.c": "fa16b72832a4cda8fd9909d88c8a7b779d352bbfb13acf76d57391dfe9219821",
    "cascade/runtime/runtime.py": "8b7899fc7aedb2de04cb900876987e6b3385922d4e2e53c913562659913818f4",
    "cascade/runtime/controls.json": "483fa566e1030e489f5bb2958bcada9f1f95762f83104b7b9e8437c360787ee5",
    "cascade/interval_extension.py": "b704413c6fddd24128fe1d2185de2aff780a6d8b7c5924f9dfebb35fcf561dae",
    "cascade/interval_extension.json": "43b7f352f14cc87b1c0452338334f9dbde3db74abdfd16dab2ff726adb269037",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pin_paths():
    return {
        "rijndael256_controls/controls.json": PRIMITIVE / "controls.json",
        "rijndael256_controls/controls.py": PRIMITIVE / "controls.py",
        "rijndael256_controls/build_source.py": PRIMITIVE / "build_source.py",
        "rijndael256_controls/js_blocks.js": PRIMITIVE / "js_blocks.js",
        "rijndael256_controls/source/aes.js": PRIMITIVE / "source/aes.js",
        "rijndael256_controls/source/rijndael-256.c": PRIMITIVE / "source/rijndael-256.c",
        "cascade/runtime/runtime.py": CASCADE_RUNTIME / "runtime.py",
        "cascade/runtime/controls.json": CASCADE_RUNTIME / "controls.json",
        "cascade/interval_extension.py": CASCADE_INTERVAL / "interval_extension.py",
        "cascade/interval_extension.json": CASCADE_INTERVAL / "interval_extension.json",
    }


def verify_pins():
    for label, path in pin_paths().items():
        got = sha(path)
        if got != PINS[label]:
            raise AssertionError((label, got, PINS[label]))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def build_sources(directory: Path):
    verify_pins()
    builder = load_module("astra_r256_primitive_builder", PRIMITIVE / "build_source.py")
    cascade = load_module("astra_r256_cascade_runtime", CASCADE_RUNTIME / "runtime.py")
    rlib = directory / "rijndael256.dylib"
    rcommand = builder.build(rlib)
    existing = cascade.build_source_libraries(directory / "cascade")
    return rlib, rcommand, cascade, existing


class Rijndael256Backend:
    block_size = BS

    def __init__(self, name: str, library: Path):
        if name not in KEYS:
            raise ValueError("unknown Rijndael-256 key variant")
        self.name = name
        self.key = KEYS[name]
        self.library_path = str(library)
        self.lib = ctypes.CDLL(str(library))
        prefix = "rijndael_256_LTX_"
        size = getattr(self.lib, prefix + "_mcrypt_get_size")
        size.argtypes = []
        size.restype = ctypes.c_int
        block_size = getattr(self.lib, prefix + "_mcrypt_get_block_size")
        block_size.argtypes = []
        block_size.restype = ctypes.c_int
        self.set_key = getattr(self.lib, prefix + "_mcrypt_set_key")
        self.set_key.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
        self.set_key.restype = ctypes.c_int
        self.encrypt_fn = getattr(self.lib, prefix + "_mcrypt_encrypt")
        self.decrypt_fn = getattr(self.lib, prefix + "_mcrypt_decrypt")
        self.encrypt_fn.argtypes = self.decrypt_fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte)]
        self.encrypt_fn.restype = self.decrypt_fn.restype = None
        assert block_size() == BS
        self.context = ctypes.create_string_buffer(size())
        key_buffer = (ctypes.c_ubyte * len(self.key)).from_buffer_copy(self.key)
        if self.set_key(self.context, key_buffer, len(self.key)) != 0:
            raise ValueError("Rijndael-256 key setup failed")

    def _crypt(self, value: bytes, decrypt: bool) -> bytes:
        if len(value) != BS:
            raise ValueError("block length")
        buffer = (ctypes.c_ubyte * BS).from_buffer_copy(value)
        (self.decrypt_fn if decrypt else self.encrypt_fn)(self.context, buffer)
        return bytes(buffer)

    def encrypt_block(self, value: bytes) -> bytes:
        return self._crypt(value, False)

    def decrypt_block(self, value: bytes) -> bytes:
        return self._crypt(value, True)

    def cfb8(self, data: bytes, iv: bytes, decrypt: bool) -> bytes:
        if len(iv) != BS:
            raise ValueError("IV length")
        reg = iv
        out = bytearray()
        for value in data:
            transformed = value ^ self.encrypt_block(reg)[0]
            ciphertext = value if decrypt else transformed
            out.append(transformed)
            reg = reg[1:] + bytes([ciphertext])
        return bytes(out)

    def encrypt_cfb8(self, data: bytes, iv: bytes) -> bytes:
        return self.cfb8(data, iv, False)

    def decrypt_cfb8(self, data: bytes, iv: bytes) -> bytes:
        return self.cfb8(data, iv, True)

    def interval_decrypt(self, known_ciphertext: bytes, absolute_offset: int = 0) -> dict:
        plaintext = bytes(
            known_ciphertext[i] ^ self.encrypt_block(known_ciphertext[i - BS:i])[0]
            for i in range(BS, len(known_ciphertext))
        )
        return {
            "offset": absolute_offset + min(BS, len(known_ciphertext)),
            "block_size": BS,
            "plaintext": plaintext,
        }


def extended_registry(rlib: Path, cascade_module, cascade_build: dict):
    registry = cascade_module.registry(cascade_build)
    registry.update({name: Rijndael256Backend(name, rlib) for name in KEYS})
    return registry


def transform(data: bytes, name: str) -> bytes:
    if name == "forward":
        return data
    if name == "byte_reverse":
        return data[::-1]
    if name == "nibble_swap":
        return bytes(((value << 4) | (value >> 4)) & 255 for value in data)
    if name == "full_hex_reverse":
        return bytes(((value << 4) | (value >> 4)) & 255 for value in data[::-1])
    raise ValueError("transform")


def transform_interval(left: int, right: int, data: bytes, total: int, name: str):
    if name == "forward":
        return left, right, data
    if name == "nibble_swap":
        return left, right, transform(data, name)
    if name in ("byte_reverse", "full_hex_reverse"):
        return total - right, total - left, transform(data, name)
    raise ValueError("transform")


def encrypt_chain(plaintext: bytes, layers: tuple[str, ...], transforms: tuple[str, ...], ivs: tuple[bytes, ...], registry: dict) -> bytes:
    if len(transforms) != len(layers) - 1 or len(ivs) != len(layers):
        raise ValueError("chain shape")
    value = plaintext
    for index in range(len(layers) - 1, -1, -1):
        value = registry[layers[index]].encrypt_cfb8(value, ivs[index])
        if index > 0:
            value = transform(value, transforms[index - 1])
    return value


def decrypt_chain(ciphertext: bytes, layers: tuple[str, ...], transforms: tuple[str, ...], ivs: tuple[bytes, ...], registry: dict) -> bytes:
    value = ciphertext
    for index, name in enumerate(layers):
        value = registry[name].decrypt_cfb8(value, ivs[index])
        if index < len(transforms):
            value = transform(value, transforms[index])
    return value


def known_interval(ciphertext: bytes, layers: tuple[str, ...], transforms: tuple[str, ...], registry: dict):
    total = len(ciphertext)
    left, right, data = 0, total, ciphertext
    trace = []
    for index, name in enumerate(layers):
        result = registry[name].interval_decrypt(data, left)
        left = result["offset"]
        data = result["plaintext"]
        trace.append({"stage": "decrypt", "backend": name, "left": left, "right": right, "data": data})
        if index < len(transforms):
            left, right, data = transform_interval(left, right, data, total, transforms[index])
            trace.append({"stage": "transform", "transform": transforms[index], "left": left, "right": right, "data": data})
        if len(data) != right - left:
            raise AssertionError("interval length")
    return left, right, data, trace
