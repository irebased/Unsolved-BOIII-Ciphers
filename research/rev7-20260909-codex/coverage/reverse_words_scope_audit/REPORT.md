# Sweep input semantics

Identity: ASTRA.

The source contradicts the comment that `--pre` receives raw text. `sweep.rs` lines 2403–2407 remove all ASCII whitespace; lines 2559–2568 put that compact buffer into `Ctx`; lines 1938–1955 apply variants and then the pre-transform to it. The claim replay path constructs compact input again at lines 3172–3176 and passes it to `Ctx` at lines 3230–3239. The target loader preserves raw text, but that alone does not preserve it in the sweep.

The captured `reverse_words` node splits ASCII whitespace runs, reverses token order, and joins tokens with a single space. On a whitespace-free hex string it is identity. An explicit `stripws+reverse_words` composition is also identity after canonical decoding. On raw spaced input that composition equals `stripws`, rather than the original spaced bytes.

A synthetic input `12 34567 89ABC` demonstrates the distinction: raw token reversal gives `89ABC 34567 12`; compact-before-reversal gives `123456789ABC`. Full character reversal is different again. A copied-source inventory and the actual Rust whitespace control also establish that vertical tab is not in Rust's ASCII-whitespace predicate; the independent Python model uses the same set.

The observed leading short token supports a reversal inference only under assumptions about earlier formatting. Both token reversal and character reversal fit ordinary left-to-right width-five grouping. Original right-aligned or manual grouping also permits a leading short token without any reversal. No historical formatting operation is proved by the token lengths alone.

The selected prior ASTRA files describe four direct orientations, an octal serialization probe, and grouped-prefix alignment. No exact raw five-token-order transform was found in that bounded corpus. Existing exclusions remain valid within their stated four-orientation scope. Global hex-symbol counts survive token permutation; byte pairing, Bifid typed graphs, periodic residue classes and CFB constraints generally do not. Those input-dependent certificates must be recomputed for a new input.

Default replay verifies every retained source excerpt against its full immutable source bytes and compiles only the target-free whitespace control. This report makes no cipher exclusion and runs no target search.
