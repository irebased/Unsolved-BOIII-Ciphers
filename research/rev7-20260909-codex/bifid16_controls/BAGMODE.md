# QF_BV byte-bag relaxation controls

This separate controls-only model keeps the same arbitrary 4x4 Bifid decryption equations while replacing the exact UTF-8 DFA with a necessary byte-membership predicate.

Bag 165 contains TAB/LF/CR, ASCII 32 through 126, continuation bytes 80 through BF, and lead bytes C2, C3, and E2. Bag 213 contains the same 98 ASCII/control bytes and continuation range, plus every valid modern UTF-8 lead-byte value C2 through F4.

The solver uses sixteen distinct four-bit square positions. Rows and columns use Extract, output coordinates use Concat, inverse lookup returns a four-bit plaintext symbol, and paired plaintext nibbles use Concat to form a byte. SolverFor QF_BV is used without integer conversion or symmetry breaking.

A prefix length constrains exactly the first requested decoded bytes. UNSAT for a prefix proves the complete stream cannot satisfy that bag. SAT means only that the prefix has a compatible square and byte bag; it does not establish UTF-8, English, or a complete plaintext. Unknown is unresolved.

Controls:

- with twelve square symbols fixed, independent enumeration of all 24 completions exactly matches complete SMT model sets for both bags;
- a full 546-byte, period-31 plant with the truth square fixed returns its exact plaintext for both bags;
- unknown-square 48-byte plants are SAT for both bags and retain complete square/plaintext models;
- unknown-square 546-byte plants at prefix lengths 64 and 128 retain their SAT/UNSAT/unknown states and any SAT models, all checked by concrete full-stream decrypt/re-encrypt.

All tested unknown-square prefix controls were SAT. They are implementation controls, not recovery evidence. No Rev7 input was read.
