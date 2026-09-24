# How go-pcre/v2 works internally

This package is a cgo binding to PCRE2's 8-bit library (`libpcre2-8`).
There is no C shim: every call goes straight through cgo
(`#cgo pkg-config: libpcre2-8`, `PCRE2_CODE_UNIT_WIDTH 8`,
`#include <pcre2.h>`). A `#error` in the preamble enforces the
libpcre2 >= 10.34 floor at build time.

File layout: `handle.go` (C memory lifetime), `pcre2.go` (compile),
`info.go` (pattern facts), `matcher.go` (match state, accessors),
`find.go` (iteration protocol), `replace.go` (replace loop + substitute),
`jit.go`, `names.go`, `config.go`, `parse.go`, `consts.go`.

## Ownership: C pointers behind handles (the v1 trick is dead)

v1 copied the compiled PCRE1 pattern into a Go `[]byte` and freed the C
side - viable because a PCRE1 pattern was one self-contained,
position-independent block. A `pcre2_real_code` is not: it embeds live
pointers (character tables, JIT data, allocator), so v2 owns C memory
behind small handle types instead:

```
codeHandle = handle[pcre2_code]        freed by pcre2_code_free
matchData  = handle[pcre2_match_data]  freed by pcre2_match_data_free
```

Both are instances of one generic `handle[T]` (`handle.go`), generalized
from v1's `extraHandle`:

- `runtime.AddCleanup` (Go 1.24) frees the block when the handle becomes
  unreachable - the backstop, not the API;
- explicit, idempotent `Free()` (`sync.Once` + cleanup.Stop + nil-swap)
  for deterministic release; use-after-free panics with a clear message
  naming the Go owner (Regexp or Matcher);
- **the pointer is never handed out**: every C call goes through
  `use(h, func(p P) R)` (`use2` for `pcre2_match`, which reads both
  blocks), which runs `runtime.KeepAlive` after the call so a cleanup
  cannot fire mid-call. The prior-art Jemmic wrapper omits the KeepAlive -
  a latent free-during-call bug; here forgetting it is impossible rather
  than merely reviewed for. The closure on the `pcre2_match` path is not
  measurable against the cgo round trip (interleaved BenchmarkExecJIT
  runs against a hand-written variant differed by about 2%, inside the
  5-10% layout noise of that benchmark);
- an atomic freed-counter per block type (`codesFreed`,
  `matchDatasFreed`) exists purely as a test hook for the GC tests.

`Regexp` is `{code *codeHandle; matchers *sync.Pool; groups int; utf,
crlfNewline bool}` - freely copyable; all copies share the handle and the
pool. The three facts are queried once at compile time
(`PCRE2_INFO_CAPTURECOUNT`, `PCRE2_INFO_ALLOPTIONS`, `PCRE2_INFO_NEWLINE`);
the bools steer the iteration advance (below), `groups` sizes every
Matcher bound to the pattern.

## Match state lives in pcre2_match_data

Each `Matcher` owns one `matchData`, created via
`pcre2_match_data_create_from_pattern` when the Matcher first binds to a
Regexp and reused for every subsequent match - reuse is blessed by
`pcre2api.3`, which also demands per-thread ownership; that maps 1:1 onto
the inherited v1 contract (shared `Regexp`, per-goroutine `Matcher`).
`Matcher.init` keeps the match data when re-bound to the same handle and
frees the old one deterministically when switching patterns.

The ovector is aliased, not copied:

```go
m.ovector = unsafe.Slice(C.pcre2_get_ovector_pointer(md), 2*(groups+1))
```

The alias is safe precisely because the Matcher owns the match data - they
live and die together. Two hard rules learned from PCRE2's semantics and
prior-art bugs govern every accessor:

- offsets are unsigned `PCRE2_SIZE`; an unset group is `PCRE2_UNSET`
  (`~0`), so the check is `== unset` - a `>= 0` guard is dead code;
- `pcre2_match` leaves the ovector **unchanged** on a failed match (v1's
  `pcre_exec` reset it to -1), so every accessor gates on `m.Matches`
  first, never on ovector sentinel values.

Both rules are enforced in one function, `span`; the only other reader of
the ovector is the aliasing in `init`. The stateless helpers never touch
it: they call `match` (the native-startoffset primitive) and consume the
whole-match span it returns, so `FindIndex`, `FindString`, `iterate` and
the Matcher accessors are all consumers of the same primitive.

`exec` passes the subject zero-copy (`&b[0]` + length; empty subject -> a
1-byte dummy with true length 0) and takes a native `startOffset`. String
subjects are converted once per call; the copy doubles as `SubjectB`, so
`Group` always slices the bytes and `GroupString` falls back to them for
a byte subject (unlike v1, `Group` has no fallback into `GroupString`:
that mutual fallback recursed forever on a nil subject). Match failures
other than NOMATCH/PARTIAL become `*MatchError` in `m.Error` - no panics.
The stateless helpers report such a failure as no match (v1 parity,
pinned by `TestHelpersReportMatchErrorAsNoMatch`); `putMatcher` drops the
error together with the pooled Matcher.

## Matcher pooling for the stateless helpers

`Regexp.MatchWFlags`, `Find*` and `ReplaceAll` are stateless per call; a
naive implementation creates and abandons a C match_data each time (C
malloc + cleanup churn - measured 5-8x slower than v1). Instead each
`Regexp` carries a `sync.Pool` of Matchers bound to its pattern (shared by
all copies, like the code handle).
Helpers take one, match, and put it back with subject references cleared
(no pinned caller memory, no stale results). Pool entries reference the
handle back; that cycle is collected as a unit and the match-data cleanup
still runs. `NewMatcher`/`NewMatcherString` stay user-owned, unpooled.

## Iteration: the canonical global-match protocol

`find.go`'s `iterate` implements the loop that pcredemo.c always
documented and PCRE2 10.47+ codified as `pcre2_next_match` (too new for
our floor; the logic is ported from `pcre2_match_next.c`):

1. match at `offset` over the **whole** subject (native startoffset - so
   `^`, `\b`, lookbehind see real context; also no double-exec of the
   first match);
2. empty match -> retry at the same offset with
   `NOTEMPTY_ATSTART|ANCHORED`; if the retry fails, bump-along and resume
   the normal search;
3. a match whose start lies after its own end or before `offset` (`\K`
   inside a lookaround, which only compiles on libpcre2 < 10.38) abandons
   the run, as pcre2demo.c does and as `pcre2_substitute` does with
   BADSUBSPATTERN;
4. otherwise continue at match end.

`bumpAlong` advances one code unit, extended two ways, mirroring the
library's `do_bumpalong`: whole UTF-8 characters when the pattern was
compiled with `PCRE2_UTF`, and CRLF as one atomic unit when the pattern's
newline convention includes CRLF - both driven by the facts cached on the
Regexp at compile time.

`ReplaceAll` is the same protocol feeding a literal-replacement builder;
its ASCII outputs are verified byte-for-byte against Perl `s///g`
(`TestReplaceAll`), and `TestReplaceAllAgainstSubstitute` proves
the loop equals `pcre2_substitute(GLOBAL)` on the whole conformance
matrix. `ReplaceAllTemplate` goes through `pcre2_substitute` directly
(`$1`/`${name}` templates), with the `OVERFLOW_LENGTH`
probe-then-retry-once buffer protocol and `UNSET_EMPTY` on.

## JIT

`Study(flags)`: 0 -> no-op (PCRE2 studies at compile time); JIT flags ->
`pcre2_jit_compile`, which **mutates the code block in place** - hence the
"fully constructed" rule: JIT compilation must complete before the Regexp
is shared. JIT data is freed by `pcre2_code_free` together with the
pattern; it is never copyable, which is why compiled patterns are not
copied at all. Two observability APIs close v1's silent-degradation hole:
`JITAvailable()` (`pcre2_config(PCRE2_CONFIG_JIT)`) and
`Regexp.JITCompiled()` (`PCRE2_INFO_JITSIZE`, a `size_t` output, read
through `infoSize`). Only the default, thread-safe JIT stack is
used; `pcre2_jit_match` (skips sanity checks) is deliberately not the
default path.

## Concurrency contract

Unchanged from v1 and identical to PCRE2's own (`pcre2api.3`
MULTITHREADING): a fully constructed Regexp (compiled + JIT done) is safe
for concurrent matching; each goroutine needs its own Matcher; `Free` must
not race with use. Validated under `-race` by TestConcurrent.

## Pattern facts

`pcre2_pattern_info` writes through a pointer whose C width depends on the
key (uint32 for most, size_t for SIZE/JITSIZE, a pointer for NAMETABLE and
FIRSTBITMAP), so the width is decided once, by key, in `info.go`
(`info32`, `infoSize`; `#cgo noescape` plus `#cgo nocallback`, cgo needs
both, keep the output variable on the Go stack). The immutable facts a Regexp needs at match time - capture count,
UTF, newline convention - are queried once in `Compile` and cached on the
Regexp, so binding a Matcher costs no cgo round trip; `Groups()` serves
the cache after the handle check. `Regexp.Info` exposes the numeric keys
to callers; `JITCompiled` (size_t) and `CaptureNames` (the table pointer)
are the typed front ends for the special ones.

## Names, config, flag parsing

The 8-bit name table format is unchanged from PCRE1 (2 bytes group number
MSB-first + NUL-terminated name); `CaptureNames` parses it from
`INFO_NAMETABLE`. `GroupNumbersForName` uses
`pcre2_substring_nametable_scan` to enumerate DUPNAMES groups; `Named*`
map `PCRE2_ERROR_NOUNIQUESUBSTRING` to `ErrNonUniqueName`. `Config` uses
PCRE2's two protocols (uniform `uint32` numerics; NULL-probe-then-buffer
strings). `ParseFlags` keeps v1's lenient historic scanner (a byte loop over the
leading `(?letters)` groups: no pattern is compiled at package init and no
cgo call is made);
`ParseFlagsStrict` only consumes groups made entirely of known flag
letters - everything else goes to the engine, which parses Perl's inline
modifiers natively.

## Verification battery

Every cgo-touching change runs: `go vet`, full tests, `-race`, and
`GOEXPERIMENT=cgocheck2` (strict cgo pointer-passing checks), plus the
GC tests against the freed-counters. Benchmarks compare against the v1
baseline on the same machine (see README).
