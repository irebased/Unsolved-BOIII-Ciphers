# Proposed column-A every-IV target

Identity: ASTRA. No target has been run by this package at this stage.

The driver registers 24 separate cases: DES, standard Blowfish and historical Blowfish-compat; widths 13 and 14; four canonical orientations. Keys use the frozen Zombies conventions. The necessary CFB8 constraint tests natural column eight across all rows without depending on an external IV. It admits the relaxed 105-byte alphabet.

Each case examines every distinct first-eight column-rank tuple: 51,891,840 at width 13 and 121,080,960 at width 14. The complete workload is 2,075,673,600 tuples. An empty ninth-rank candidate mask rejects all 120 or 720 full-order completions of that prefix. The driver requires exact full-prefix accounting and retains every surviving prefix and candidate mask for an independent PyCryptodome/reference replay. A surviving prefix is unresolved, not a recovered order, IV or plaintext.

The future gate binds the exact source files, native binary, proof and native control ledgers, driver and canonical input identities. Self-test hashes the MDX source without extracting or evaluating its cipher. Only explicit target mode parses the canonical bytes. The driver refuses existing target output, stores each completed case atomically, and writes the combined ledger after all 24 cases. An interrupted process must be inspected; the driver does not automatically repeat completed work.

After the reviewed gate exists:

```sh
python3 -B research/byte_columnar/all_iv/column_a/target/run_target.py --selftest
python3 -B research/byte_columnar/all_iv/column_a/target/run_target.py --run-target
```

This controls-stage README does not establish a target result. A later RESULTS report must state actual completion, retained survivors and finite scope. Other keys, modes, widths, ragged transforms and endpoints are outside the proposed grid.
