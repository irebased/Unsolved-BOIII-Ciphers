# Encoded endpoint search

```json
{
  "identity": "ASTRA",
  "status": "target completed: 48 exhaustive empty cells; 12 capped empty cells",
  "scope": "Five separately certified encoded-text endpoints over three CFB8 ciphers and four direct hex orientations"
}
```

`run_encoded.py` reuses the independently controlled partial-bijection DFS in `../prototype.py`. Each target cell is capped at 1,000,000 DFS entries. A DFS entry is an accepted ciphertext/plaintext prefix and causes one ECB operation unless terminal. Rejected mapping choices are counted separately.

The five endpoint byte sets each contain TAB, LF, CR, and space, plus exactly one of: `AB`; `01234567`; `0123456789`; `0123456789ABCDEF`; or the ASCII Base64 alphabet with `=`. The alphabets overlap: `AB` is not a subset of octal or decimal, while every named content alphabet is a subset of Base64. Every endpoint is run as its own search and receives its own factorial completeness certificate; coverage is never summed or inferred between them. The target grid therefore has 5 × 3 × 4 = 60 cells.

Synthetic controls:

```sh
cd research/rev7-20260909-codex/hex_cfb/encoded
python3 run_encoded.py --controls
```

Target execution is deliberately explicit and was not run while preparing these controls:

```sh
python3 run_encoded.py --run-target
python3 run_encoded.py --run-target --resume  # only after an interrupted checkpoint
```

Before reading Rev 7, the target command requires `controls.json` and checks its identity, target-false flag, source hashes, exact configuration, four complete unseeded gates, the explicitly labelled Base64 fallback when needed, and all fifteen complete naive comparisons. The frozen control SHA-256 becomes part of the target configuration and resume guard. The target command refuses an existing final output. It also refuses an existing checkpoint unless `--resume` is supplied and its full configuration, input hash, and source hashes match. Each cell is atomically checkpointed. Every survivor is independently decrypted and re-encrypted with PyCryptodome CFB8 (`segment_size=8`) and must reconstruct the oriented displayed hex exactly.

An uncapped cell is complete only when rejected and terminal subtree weights total `16!`. A capped cell is explicitly incomplete and cannot support a negative claim.


## Recorded result

`target_results.json` records all 60 target cells. For AB, octal, decimal and uppercase hex, all 12 cipher/orientation cells finished with zero survivors and exact rejected weight `16! = 20,922,789,888,000` per cell. DFS node ranges per cell were 31–102, 260–609, 455–1,195 and 2,132–5,592 respectively. All twelve Base64 cells hit their 1,000,000-entry cap with zero observed survivors; they remain incomplete.

The exact cipher conventions come from `../prototype.py`: AES128 with `b"Zombies" + 9*NUL`, standard Blowfish with raw seven-byte `b"Zombies"`, DES with `b"Zombies" + NUL`, and ASCII-zero IVs at the cipher block size. The four orientations are forward, complete hex-character reversal, byte-order reversal, and per-byte nibble swap. All outputs must consist of 546 allowed bytes. These results do not cover other cipher/key/IV/mode conventions, other text alphabets or case variants, wrappers, framing, corruption, or binary intermediates.

The four smaller unseeded AES control plants recovered the planted full bijection and exhausted the full space. The Base64 unseeded plant capped before recovery; its separate 12-seeded/4-unknown fallback recovered the plant and exhausted 4! mappings. All fifteen endpoint/cipher controls compared complete survivor mapping/plaintext sets with 24 independent PyCryptodome decryptions. The seeded Base64 fallback is not evidence that the capped unseeded search recovers every plant.

SHA-256:

- `run_encoded.py`: `b2359b18171523ee4bc37cab4d6bab6a5633dba72e28f76d6fae98898ac22b3c`
- `controls.json`: `55a765402a520a9d945bb55a3a1b3876875aab7593c87b0463097740f43dc0ab`
- `target_results.json`: `135f5479c05d10d756c9e94af217547b64addec24aa4c2e6ba94d18618f8688f`

The capped broad-text search in the parent directory is separate from this smaller-alphabet run. Neither experiment recovered a Rev7 layer.
