# Exact 201-codepoint suffix control results

Identity: **ASTRA**

The automaton agrees with the independent strict-decoding prefix oracle for all 201 complete codewords and all 65,793 byte strings of length zero through two. The explicit `80` control confirms existential boundary acceptance; `E2 93 80` confirms that membership in the 165-byte union is insufficient. All 12 frozen source maps reproduce their expected 4,096- or 256-register geometry.

| Plant | Roots | Status | Terminal candidates | Accepted states | Block calls | Maximum frontier | Truth |
|---|---:|---|---:|---:|---:|---:|---|
| short99 drop1, two-byte cut | 4,096 | complete | 1,056 | 175,299 | 178,323 | 168 | retained once |
| short99 drop3, three-byte cut | 256 | complete | 468 | 46,816 | 46,592 | 371 | retained once |
| full655 drop1, three-byte cut | 4,096 | INCOMPLETE: global accepted cap | 7,280 completed-root terminals | 5,000,000 | 4,995,481 | 2,149 | not claimed; 681 roots unexamined |
| full655 drop3, two-byte cut | 256 | complete | 4,992 | 2,354,641 | 2,349,489 | 8,484 | retained once |

Both deterministic nulls completed with zero terminal candidates. The 4,096-root null accepted 400,290 states; the 256-root null accepted 20,461. Both one-state cap controls are INCOMPLETE with zero partial paths labeled terminal.

The controls establish implementation and accounting for the exact endpoint. They make no target claim, do not recover the original IV or first eight plaintext bytes, and do not treat a capped positive control as accepted.
