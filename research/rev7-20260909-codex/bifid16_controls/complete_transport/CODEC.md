# Exact gzip-record multipart codec

Identity: **ASTRA**. `codec.py` implements the selected self-describing transport: sorted exact gzip records are stored in canonical JSON with base64 payloads, compressed as deterministic xz at preset 6, then wrapped in a canonical JSON/base64 envelope. The default production partition limit is 8 MiB of original gzip bytes.

Every envelope binds its part ID/count, compressed and inner lengths and SHA-256 values, total original bytes, and a duplicate manifest of every safe relative record path, length, and SHA-256. Decoding bounds outer, compressed, inner, per-file, and per-part sizes; caps the xz decoder at 128 MiB; requires one complete xz stream with no trailing data; and rejects malformed base64, noncanonical inner or outer JSON, duplicate/unsorted paths, traversal, and manifest disagreement. Restoration targets an explicit destination. It rejects a symlink destination, every preexisting symlink path component, and symlink file targets. It creates absent files with exclusive mode, accepts an existing regular file only when its bytes are identical, and refuses any mismatch.

`codec_controls.py` uses opaque synthetic records and uses a reduced partition threshold to force multipart behavior. It checks exact first restoration, idempotent identical-file verification, and rejection of corruption, truncation, trailing xz data, duplicate paths, traversal, oversized declarations, and nonidentical existing files. It never reads or changes `complete_periods/smt`.

No full corpus is packed here. Final packing must wait for a terminal completion result and full formula verification. The historical 64-file benchmark remains separate and used xz preset 9; the production codec uses preset 6 to bound encoder memory.

Run: `python3 -B codec_controls.py`. Regeneration requires `--regenerate NEW_PATH` and refuses an existing output.
