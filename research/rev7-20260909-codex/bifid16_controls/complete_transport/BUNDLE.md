# Gate-locked complete-period formula bundle

Identity: **ASTRA**. `bundle.py` is an inert wrapper for the accepted exact-record codec. It cannot pack, verify, or restore a production package until root creates `pack_gate.json`. That gate must pin the terminal result and checkpoint, the successful full-formula verification receipt, and every codec/wrapper dependency. The wrapper calls no solver.

A production pack requires exactly 2,175 result rows and exactly the matching on-disk formula set. Before packing it checks every original gzip length/SHA and bounded-decompresses every record to verify the raw SMT SHA. It partitions sorted records at 8 MiB of original gzip bytes and exclusively creates a new parts directory. `manifest.json` binds the result, checkpoint, gate, verification receipt, every part, and every record path plus exact gzip and raw-SMT metadata.

Verification decodes every part, enforces consecutive consistent part IDs/counts, globally unique ordered paths, the exact 2,175-row union, result metadata, and every gzip/raw-SMT hash. Restoration requires an explicit destination and delegates symlink/overwrite safeguards to `codec.py`. Existing package outputs are refused.

`bundle_controls.py` is synthetic-only. It creates 2,175 tiny deterministic opaque gzip records in a temporary directory, exercises multipart packing, complete ordered-union verification, exact restoration, and six rejection cases: reversed parts, noncanonical filenames, duplicate/count mismatch, original-byte mismatch, invalid partition limits, and oversized part files. The wrapper validates each expected filename and file-size bound before opening a part. It never reads the production formulas or target ciphertext.

No full corpus, production manifest, or gate is included. Root must wait for terminal full-formula verification before creating the gate and invoking `--pack`.
