# bench-corpus

Fixed synthetic source tree consumed by `tests/bench-suite.sh` for the
Tier-2 application benchmarks:

- `git status` walks it as a freshly committed repository,
- `rg` searches it for `syscall_entry_` definitions,
- `make` runs its `Makefile` (BusyBox-only rules, no compiler),
- `zstd` compresses a concatenation of its files.

The content is deterministic output of a one-shot generator and is part
of the benchmark definition: editing, reformatting, or regenerating it
changes every measurement and invalidates `tests/bench-baseline.json`.
Do not modify these files; if the corpus ever must change, regenerate
the baseline in the same change (see the header of
`tests/bench-suite.sh` for the refresh procedure).
