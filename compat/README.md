# compat: v1 vs v2 differential suite

This module runs a shared corpus of (pattern, subject, flags) cases
through go-pcre v1 (PCRE 8.x) and go-pcre v2 (PCRE2) in one binary and
compares every observable output: compile result and error offset, match
and partial status, match errors and panics, group spans, extracted
captures, named-group lookups, FindIndex/FindAllIndex, and ReplaceAll.

Its purpose is to prove the divergence list in ../MIGRATION.md complete:
every difference the corpus can provoke must be classified as one of the
documented divergences (D1..D13) or a documented dialect change; anything
unexplained fails the test and lands in the report.

## Layout requirement

The two libraries are different major versions of the same repository, so
the suite needs both branches on disk at once:

- `..` (the parent of this directory): the `pcre2` branch (v2 sources).
- `../../go-pcre`: a sibling checkout of this repository with the
  `pcre8.x` branch checked out (v1 sources).

Both C libraries must be resolvable by pkg-config: `libpcre` (8.x, built
with JIT) and `libpcre2-8` (>= 10.34).

## Running

```bash
cd compat
go test            # run the corpus, write report.md
go test -race
GOEXPERIMENT=cgocheck2 go test
go test -run 'TestDiff/basic/literal'   # reproduce one case
```

A full run regenerates `report.md` (a filtered `-run` keeps the committed
one): unexplained differences first (each
with a repro command), then counts of known divergences by tag, then the
ConfigAll dumps of both libraries.

## Adding cases

Add a `Case` to the matching `corpus_*.go` file (or a new category file
wired into `allCases`). A case with `Known` tags MUST produce at least
one difference (the suite fails when a documented divergence stops
reproducing); a case without `Known` must produce none beyond the global
rules (compile-error wording, D3).
