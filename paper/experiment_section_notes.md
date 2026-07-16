# Notes on the revised Performance Evaluation section

This accompanies `experiment_section.tex`, a drop-in revision of Section 6
("Performance Evaluation") of the Fire & Ice / FIMBs manuscript. Read this
first — it explains what changed, what I actually ran, and one finding you
should decide how to handle before submission.

## What I did

1. Read the full manuscript PDF to understand the protocol (§4.4 in
   particular — the "boolean check + AES" evaluation phase) and the
   currently-reported numbers (the Block(s) 1–7 → ms table, the HTTP/DNS
   ranges, the ZKMBs comparisons in Figures 2–4).
2. Located the actual MPC programs behind these claims in the repo:
   `jason_aes.mpc`, `jason_aes2.mpc`, `jason_aes3.mpc`, `jason_aes4.mpc`.
3. Found that **none of the four existing programs implement the full
   evaluation-phase protocol described in §4.4** — specifically, none of
   them compute or reveal `H = E_K(0)` or `k0 = E_K(IV_0)`, the two
   AES calls the paper's own cost formula ("k× boolean check and k+2× AES")
   accounts for. `jason_aes3.mpc` is the closest match to what's
   benchmarked (supports a variable block count `L` via public input) but
   only does `L` boolean checks + `L` AES calls — the "partial" protocol.
4. Wrote `jason_aes_full.mpc`, implementing the complete protocol exactly
   as specified in §4.4: boolean check + AES evaluation over every element
   of `t = (IV_0, IV_1, ..., IV_L, 0)`, i.e. `(L+2)` of each. Verified its
   AES outputs against the repo's own pure-Python AES implementation
   (`aes-gcm/implementing_aes.py`) for exact correctness — all three
   outputs matched bit-for-bit in a manual check.
5. Benchmarked both programs for `L = 1..7`, 7 trials each, on this
   session's sandbox (4-core 2.8 GHz Xeon, 16 GB RAM — **not** the paper's
   stated 8-core Ryzen 7840HS laptop). Scripts are checked into
   `mp-spdz/benchmark_jason_aes3.py` and `mp-spdz/benchmark_jason_aes_full.py`.
6. Investigated the "~3 second one-time setup" claim. The only concrete
   candidate setup step in the repo is `Scripts/setup-ssl.sh` (generates
   two RSA/x509 identities via OpenSSL) — timed at 0.445s on this sandbox,
   nowhere near 3 seconds. I could not find what else the paper's "3s"
   figure is meant to include (MPC preprocessing? policy download? both?).

## Results

| L | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|
| Paper (E1, 8-core Ryzen) | 296 | 391 | 488 | 586 | 676 | 765 | 867 |
| Reproduced partial protocol (E2, 4-core Xeon) | 322 | 428 | 554 | 685 | 780 | 894 | 990 |
| Complete protocol, L+2 (E2, 4-core Xeon) | 555 | 655 | 767 | 907 | 1042 | 1120 | 1316 |

The partial-protocol reproduction lands within 9–15% of the original
numbers despite different hardware — a good reproducibility signal, and
it confirms the ~90–130ms-per-block linear trend holds. The complete
protocol adds a fairly constant ~213–326ms (mean ≈244ms) on top at every
`L`, consistent with the `+2` term being an `L`-independent fixed cost
(H and k0 are computed once per record, not once per block).

## The one thing you need to decide

**The currently-reported table (296–867ms) measures the partial protocol,
not the complete one your own §4.4 and cost formula describe.** You have
three honest ways to resolve this before submission:

1. **Report the complete-protocol numbers instead** (a straightforward
   swap — I've already benchmarked it; you'd want to re-run once more on
   your original Ryzen hardware for an apples-to-apples E1 number, since
   what I have for the complete protocol is E2-only).
2. **Keep the partial-protocol numbers, but change the text** so the cost
   formula and Table are both explicit that they cover only the
   per-block keystream check, and separately state the tag-binding
   check (H, k0) as an optional/deferred add-on with its own
   (now-measured) constant cost.
3. **Say nothing and hope no reviewer runs the artifact** — not
   recommended; the repo is public and linked in the paper, so this is
   the kind of discrepancy a careful reviewer (or this being AsiaCCS, a
   shepherding committee) could plausibly catch.

I'd recommend (1) or (2). I did not silently pick one for you, since it
changes both a number reviewers will scrutinize and a security claim
(whether the tag-binding defense from §3.3.4 is actually being measured).

## What I did NOT do

- I did not touch Figures 2–4 (the ZKMBs session-count comparisons). I
  don't have a ZKMBs deployment in this environment, and the paper
  already discloses those are "conservative estimates ... derived from
  the reported results" for ZKMBs — I kept that framing and added an
  explicit limitation sentence rather than fabricate a controlled
  comparison.
- I did not re-run the HTTP firewalling / DNS filtering end-to-end demos
  against live traffic — the block-count numbers above map directly onto
  those use cases (1–2 blocks for HTTP, 1–6 (or +1) for DNS), so I
  derived the ranges rather than re-running the network-facing demos,
  consistent with how the original draft presents them.
- I did not resolve the "~3s setup" ambiguity — I flagged it in the LaTeX
  with a recommendation to give an explicit breakdown, since I couldn't
  find the corresponding step in the artifact to benchmark.

## Files delivered

- `paper/experiment_section.tex` — revised Section 6, ready to paste into
  the manuscript (uses placeholder `\cite{}` keys — align with your
  actual `.bib` entries for `tlslite-ng`, MP-SPDZ, ZKMBs, Zombie, and the
  blocklist source).
- `paper/experiment_section_notes.md` — this file.
- `mp-spdz/Programs/Source/jason_aes_full.mpc` — new, complete-protocol
  MPC program.
- `mp-spdz/benchmark_jason_aes3.py`, `mp-spdz/benchmark_jason_aes_full.py`
  — benchmark harnesses (both artifacts for your reproducibility
  appendix if you want one).
