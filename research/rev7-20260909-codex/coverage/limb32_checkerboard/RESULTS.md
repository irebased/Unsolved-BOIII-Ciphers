# Limb-local decimal checkerboard result

Identity: ASTRA.

The single preregistered run completed successfully in exec session `74569` with exit status 0. Command:

```sh
python3 -B research/rev7-20260909-codex/coverage/limb32_checkerboard/run_target.py --run-target
```

The frozen 1,440-cell parse grid contains **1,220 complete parses** and **220 dangling-header failures**. Of the complete rows, **1,214 use all 28 checkerboard cells** and **six use 27**. No row is a complete decode under the documented 26-cell Rev3 board with headers 3 and 7. Exact token-tuple deduplication produced 1,220 unique streams; it is not equality-pattern normalization.

The target result is 1,290,793 bytes with SHA-256 `cdd5dfde536cbd48048e2f367b9088d62f76e5070db2fe8deab162064652cba5`. The gate SHA-256 is `d4b970235c181a4d2e7f29dd3c90c9f526b7fdd2a729a71d627b5cef7d026130`; the driver SHA-256 is `104a42e6543603fb8a1076c686182ed8ee8b13cbfbbca4a67d05f7f081adc64e`. The observed Codex tool lifecycle was about 79 seconds including parsing, serialization, JSON construction and annealing; the result schema did not separately instrument algorithm time. Python was `3.9.6`.

The heuristic selected the first 20 exact token streams by descending token IoC and ran four deterministic 6,000-step substitution restarts on each. Every retained mapping reconstructs its token stream. The best restart per selected stream was:

| Rank | Candidate ID | Token IoC | Restart | Score | Plaintext SHA-256 |
|---:|---|---:|---:|---:|---|
| 1 | `ori=full_hex_reverse|endian=big|limbs=forward|digits=reverse|headers=7,9` | 0.092161006397 | 3 | -15674.463423 | `90bff0ab80355a37ef8f81f9ddd33ff7fd7f287472ab4a06dfd876d3c30eefae` |
| 2 | `ori=full_hex_reverse|endian=big|limbs=reverse|digits=reverse|headers=7,9` | 0.092161006397 | 1 | -15644.992270 | `b3fa1658aeab8d9afd279259a236a2a53ff5928ca242fc7c9a4765a6731137f7` |
| 3 | `ori=full_hex_reverse|endian=big|limbs=forward|digits=forward|headers=7,9` | 0.092021545314 | 2 | -15656.401159 | `ff7fc5b0b9e7387317c719106965c8749534121f09ae8e0c1782176f2683d2c7` |
| 4 | `ori=full_hex_reverse|endian=big|limbs=reverse|digits=forward|headers=7,9` | 0.091977430074 | 3 | -15641.963362 | `ca55fbce312eac0f2554db4a876ef25f7816cc41d4c1ceee4e05f2b8bc4c1d9e` |
| 5 | `ori=nibble_swap|endian=little|limbs=forward|digits=reverse|headers=5,7` | 0.091178965225 | 0 | -15584.545516 | `1be42099729c21616a7d5be55c660539fa94ffd6803c89ec8b3c1492fcf9d38d` |
| 6 | `ori=nibble_swap|endian=little|limbs=reverse|digits=reverse|headers=5,7` | 0.091178965225 | 2 | -15575.745151 | `764ead5c3ced886cb0e94a5869728ef40d95cfb26dfd165c6c5a812d9ab9f3a4` |
| 7 | `ori=byte_reverse|endian=big|limbs=forward|digits=reverse|headers=5,8` | 0.091156589503 | 2 | -15603.713344 | `2278adcbfa2b222323397663524f3f8896ad320974ec7cd2e56fc564df2c4e47` |
| 8 | `ori=byte_reverse|endian=big|limbs=reverse|digits=reverse|headers=5,8` | 0.091156589503 | 0 | -15585.877212 | `456b7b5d9f5cc9cf855cc3339e96ac85f39f4ebc5b78cc54b17a90181cbf7d6a` |
| 9 | `ori=full_hex_reverse|endian=little|limbs=reverse|digits=forward|headers=6,8` | 0.091117148977 | 2 | -15584.803757 | `92484332528aea21d9ea77fc8dd5e8e718253b4b59fdf250958cf8efa5eebf0c` |
| 10 | `ori=byte_reverse|endian=big|limbs=reverse|digits=forward|headers=5,8` | 0.091000157867 | 3 | -15595.638362 | `39a96f434c21bb2cfea35bf491d806f25f31e22363e3c88f49b77861fb436cc0` |
| 11 | `ori=full_hex_reverse|endian=little|limbs=forward|digits=forward|headers=6,8` | 0.090989203720 | 0 | -15590.070640 | `3df192127ef470aa3b0f68403548e4b7891137c1f90a5556ae09a93838e65149` |
| 12 | `ori=full_hex_reverse|endian=little|limbs=forward|digits=reverse|headers=6,8` | 0.090980578198 | 2 | -15583.318008 | `53c7100cae4cf06fd2708df270e1e4df70776b6db02de2abeb1347efb77121c0` |
| 13 | `ori=full_hex_reverse|endian=little|limbs=reverse|digits=reverse|headers=6,8` | 0.090980578198 | 3 | -15585.746372 | `3787fae19536a6ec432d17662614e3f824b674f3d0d1eafd76444ada763bbd43` |
| 14 | `ori=nibble_swap|endian=little|limbs=reverse|digits=forward|headers=5,8` | 0.090979521364 | 3 | -15578.773860 | `b0ee731ba59ed4cb7247be3c3db8f7de189816582aa9e71e4243054dd5c041e4` |
| 15 | `ori=full_hex_reverse|endian=little|limbs=forward|digits=reverse|headers=6,9` | 0.090966561113 | 1 | -15574.206571 | `625312b9700811562fe1ca333f213b5454cd58abda173002dd633369edf886d5` |
| 16 | `ori=full_hex_reverse|endian=little|limbs=reverse|digits=reverse|headers=6,9` | 0.090966561113 | 1 | -15570.609434 | `1aec0845eea3aeb5d0c62a00a73059c02c4bb572c46f38577fa96e67eeae14bf` |
| 17 | `ori=nibble_swap|endian=little|limbs=forward|digits=forward|headers=5,8` | 0.090963681057 | 1 | -15572.145486 | `86819be955f41103382c4d0dd67c0bb903e80391e77e74d9f0c8bbe08ede3212` |
| 18 | `ori=nibble_swap|endian=little|limbs=reverse|digits=forward|headers=5,7` | 0.090928825060 | 1 | -15587.719473 | `78852d8780e5ef52e54c9e0b2b25fcc9140ab07ad8afb281501a1e6ca383bbe8` |
| 19 | `ori=full_hex_reverse|endian=little|limbs=reverse|digits=forward|headers=6,9` | 0.090923360276 | 1 | -15552.263964 | `378b8d81dd17f584576bc0c7759d15fe3e2cb8a7eac0ea40f550fd38baaf5cc3` |
| 20 | `ori=byte_reverse|endian=big|limbs=forward|digits=forward|headers=5,8` | 0.090893956572 | 3 | -15607.591431 | `2f8eb58465733e9b52aa375b3597ebf38074e67273742bd09f407c32be9fdd58` |

I inspected all 80 complete retained plaintexts. None contains a sustained grammatical sentence, stable topic, proper name, or plausible encoded intermediate. The longest exact substrings shared with the sibling training corpus are short common-language fragments:

- Rank 18, restart 1, `ori=nibble_swap|endian=little|limbs=reverse|digits=forward|headers=5,7`: `S THERE I` at candidate offset 417, nine characters.
- Rank 11, restart 3, `ori=full_hex_reverse|endian=little|limbs=forward|digits=forward|headers=6,8`: `. IN THE` at offset 200, eight characters.
- Rank 7, restart 3, `ori=byte_reverse|endian=big|limbs=forward|digits=reverse|headers=5,8`: `L AND NE` at offset 1,159, eight characters.

These fragments are isolated inside strings dominated by repetitions such as `TH`, `HE`, spaces and common vowels. The annealer is directly optimized against the sibling tetragram model, so snippets of this size are expected overfit evidence rather than a breakthrough. The globally highest retained score is rank 19, restart 1 (`ori=full_hex_reverse|endian=little|limbs=reverse|digits=forward|headers=6,9`, score -15552.263964); its full output is likewise incoherent.

The exact result excludes only the fixed Rev3 26-cell board inside this 32-serializer framing because all corresponding parses touch blank cells. It does not exclude an arbitrary 27/28-symbol checkerboard. The latter search is heuristic: only the top 20 of 1,220 exact token streams were annealed, with a fixed budget and a small sibling-derived A-Z/space/period model. Failure there does not exclude lower-IoC streams, other restarts, other output alphabets, homophonic assignments, a subsequent layer, or other chunk/tail rules. The u32 plus exact u16-tail serialization remains a deliberately bounded representation hypothesis, not recovered historical source behavior.

Frozen supporting evidence:

- Parser/model `1f479f1697d84ee16a2cd9f89568756b9d30878418fe810206da9c683bc14725`; parser controls `f771d92d014a02a423585d6d27adf79ae89702ba57d634770bee0560d80cb632` / ledger `51ae541d6f08c62521630d4ac4bb19c786e0348170567abb1986dae005778a96`.
- Annealer `6937961a714e4ec0e26b5d1c5584f001d8b6a381155f76b0e79c8477246c6d79`; annealer controls `e2b4befefd0ecd6c3338063976c73a63bf516c4a9c1ae499f02cd2118976d072` / ledger `43392045bdf475a16ad80fb391a1d6e54b40cfe3b62a2d0334a7da780e621615`.
- Driver controls `c6645018f20ce1aba82c925d5505504319725d3a8cde78e495382664bbe7e008` / ledger `e5070e218ccfd0fdf37c87ea2792208d61a656d1e03c1c62eaed326cf83a62c0`.
- Character model `7752ce6f93d12079cf9e567d9f0dddf37178f8b40f7907ee6d7c733383969b01`, built from solved siblings with Rev7 and held-out Rev13 excluded.
- Canonical normalized Rev7 text `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`, MDX `085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91`, dataset `68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e`.
