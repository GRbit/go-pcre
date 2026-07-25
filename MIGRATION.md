# Migrating from go-pcre v1 to v2

v2 is the same `Regexp`/`Matcher` API on PCRE2 (10.x) instead of the
legacy PCRE 8.x library. The v1 test suite is v2's conformance suite: every
v1 function and method exists with the same signature, and v1 code
compiles after changing the import. What differs is listed here, complete.

## Mechanics

```bash
sudo apt-get install libpcre2-dev   # replaces libpcre3-dev / hand-built PCRE
go get github.com/GRbit/go-pcre/v2
```

```go
import "github.com/GRbit/go-pcre/v2"   // package name stays "pcre"
```

Requires Go >= 1.24 and libpcre2-8 >= 10.34 (Debian 11 / Ubuntu 20.04 era).
An older libpcre2 fails at build time with a clear `#error`.

## Behavior divergences (all intentional)

Each of these is pinned by a test in the v2 suite. The API reference
tables below cite them as D1..D13.

1. **Match errors are returned, never panicked.** v1's `checkMatch`
   panicked on several reachable `pcre_exec` codes (v1 BUGS.md #7). v2
   stores a typed `*MatchError{Code, Message}` in `Matcher.Error` for every
   negative code except "no match" and "partial".
2. **Embedded NUL bytes in patterns are legal.** PCRE2 takes the pattern
   with an explicit length. v1 rejected `"a\x00bc"` at compile time; v2
   compiles and matches it.
3. **Compile errors are typed and text differs.** `Compile` returns
   `*CompileError{Pattern, Message, Offset}`. The rendered string keeps
   v1's `pattern (offset): message` shape, but PCRE2's message wording
   differs from PCRE1's. Match on the type, not the text. The offset
   usually agrees, but can drift by a character for some errors (e.g.
   `\N{name}`: PCRE1 reports offset 1, PCRE2 offset 2).
4. **Iteration is boundary-correct.** `FindAllIndex` and `ReplaceAll`
   drive PCRE2's native start offset instead of re-slicing the subject, so
   `^`, `\b`/`\B` and lookbehind see the true context at every iteration
   boundary. Examples that change vs v1: `\Biss` on `"Mississippi"` now
   finds both `[1,4]` and `[4,7]`; `(?<=a)a` on `"aaa"` finds two matches;
   `^.` on `"abc"` finds only `[0,1]`. The fake restarts also corrupted
   v1 in the other direction: with `MULTILINE`, `^.` on `"ab\ncd\nef"`
   matched mid-line (six matches instead of Perl's three), `\B\w` on
   `"abc def"` missed half its matches, and a bare `\b` on `"hi there"`
   reported one boundary twice while missing the end-of-subject one.
   v2 agrees with Perl in all of these (verified byte for byte by the
   compat suite).
5. **Empty-match advance is character-wise in UTF mode** (v1 stepped
   bytes, improvement #14) **and skips CRLF atomically when the pattern's
   newline convention includes CRLF** (`(*CRLF)`, `(*ANYCRLF)`, `(*ANY)`).
   The CRLF rule matches PCRE2's canonical protocol (`pcre2_substitute`,
   10.47+'s `pcre2_next_match`) and diverges from Perl only when a pattern
   opts into such a convention - Perl has no equivalent concept. ASCII
   outputs of `ReplaceAll` remain Perl-`s///g`-verified byte for byte.
6. **`Study(0)` is a successful no-op.** PCRE2 computes study data at
   compile time; only JIT flags do work now. Studying an already
   JIT-compiled Regexp still errors like v1. The v1 `STUDY_*` constants
   are aliases of the PCRE2 `JIT_*` ones.
7. **`NEWLINE_*` / `BSR_*` flag constants are gone.** PCRE2 moved newline
   and BSR selection to compile contexts, which v2 does not expose in this
   release. Use the in-pattern equivalents: `(*CRLF)`, `(*ANYCRLF)`,
   `(*BSR_UNICODE)`, etc.
8. **Renamed flags keep aliases**: `UTF8` -> `UTF` (alias kept),
   `NO_UTF8_CHECK` -> `NO_UTF_CHECK` (alias kept), `EXTRA` = 0 (PCRE2 is
   strict by default; the letter/constant is accepted and ignored),
   `JAVASCRIPT_COMPAT` = `ALT_BSUX|MATCH_UNSET_BACKREF`.
9. **Deterministic release exists.** `Regexp.Free()` and `Matcher.Free()`
   release the C memory immediately; GC cleanups remain as backstop.
   Using a freed (or zero-value) object panics with a clear message
   instead of crashing. Copies of a Regexp share the compiled pattern, so
   `Free` invalidates all of them.
10. **`Config` semantics.** Numeric queries are PCRE2-uniform `uint32`
    (v1's `MATCH_LIMIT` stack-smash class is impossible); `VERSION`,
    `UNICODE_VERSION` and `JITTARGET` are real strings; unknown keys and
    `JITTARGET` without JIT return `""`. `ConfigAll` lists PCRE2's keys -
    names differ from v1's PCRE1 set.
11. **Duplicate group names are first-class.** With `DUPNAMES`, `Named*`
    on a non-unique name fails with `ErrNonUniqueName` (detectable via
    `errors.Is`). v1 was silently wrong here: `pcre_get_stringnumber`
    resolves a duplicate name by plain binary search with no uniqueness
    check, so v1 returned whichever duplicate group the search landed on
    - the wrong or unset one, depending on which alternative matched -
    with no error at all. Use `GroupNumbersForName` to enumerate the
    duplicates and query them by number.
12. **`FindAllIndex` follows the Perl global-match protocol.** After an
    empty match, v1 simply advanced one byte, which skipped a non-empty
    match starting at the same offset (`|x` on `"xy"`: v1 found three
    empty matches; Perl and v2 find the empty match, then `"x"`, then
    two more) and reported the end-of-subject empty match twice (`$` on
    `"abc"`: v1 returned `[3,3]` twice). v2 iterates exactly like its
    own `ReplaceAll` (retry the same offset with
    `NOTEMPTY_ATSTART|ANCHORED`, then advance), so `FindAllIndex` and
    `ReplaceAll` now agree with each other and with Perl's `pos()` loop.
13. **`CompileParse`/`CompileParseJIT` errors wrap the `*CompileError`.**
    v1 replaced Compile's error with the generic
    `can't compile/study pcre regexp: pattern='...' flags='...'` string,
    losing the message and offset. v2 keeps that prefix, so
    `strings.HasPrefix`/`Contains` checks still work, and appends the cause
    after a colon, reachable with `errors.As`. Only code comparing the whole
    error string for equality is affected.

## Flag parsing and Perl compatibility

`ParseFlags`/`CompileParse` keep v1's lenient, historic behavior: every
leading `(?letters)` group is consumed and unknown letters are silently
dropped - which mangles `(?R)` and hides typos like `(?gi)`. Two better
options in v2:

- `ParseFlagsStrict`/`CompileParseStrict` consume a leading group only if
  every letter is a known flag letter, leaving anything else to the
  engine - `(?R)` stays recursion, `(?gi)` fails like Perl.
- Skip pre-parsing: PCRE2 natively parses Perl's inline modifiers
  (`(?i)`, `(?i-m)`, `(?^i)`, `(?i:...)`, `(?n)`, `(?U)`, `(?J)`) and the
  `(*UTF)`/`(*UCP)` verbs, with Perl's placement rules and errors. Plain
  `Compile` is the most Perl-compatible route.

## New in v2

- `ReplaceAllTemplate` / `ReplaceAllTemplateString` - `pcre2_substitute`
  replacement with `$1`/`${name}` templates; unset groups substitute as
  empty; `SUBSTITUTE_EXTENDED` opt-in for `\U`/`${n:-default}` forms.
- `JITAvailable()` and `Regexp.JITCompiled()` - JIT support/engagement is
  observable (v1 could silently run JIT-less).
- `GroupNumbersForName` - enumerate all groups behind a DUPNAMES name.
- `ParseFlagsStrict` / `CompileParseStrict` - see above.
- `Regexp.Free()` / `Matcher.Free()` - deterministic release.
- `LITERAL`, `ENDANCHORED`, `MATCH_INVALID_UTF`, `NO_JIT` and further
  PCRE2-only options are exported in consts.go.

## Complete API reference (v1 -> v2)

Every exported v1 identifier appears exactly once in this section with its
v2 replacement. "Same" means identical signature and observable behavior;
Dn refers to the numbered divergence list above. Two blanket rules cover
everything at once:

- Every constant's numeric value changed (PCRE2 renumbered its entire
  API). Code that compares symbolically (`rc == pcre.ERROR_NOMATCH`) is
  unaffected; code that hardcodes or persists the raw integers must be
  revisited. `ERROR_NOMATCH` (-1) is the only value that survived.
- Every error string changed at least in wording (D3 for compile errors;
  match and name-lookup errors gained `pcre:`/`pcre2_match` prefixes).
  Match on error types with `errors.As`/`errors.Is`, never on text.

### Package functions

| v1 | v2 | Differences |
|---|---|---|
| `Compile(pattern string, flags int) (Regexp, error)` | same signature | Error is a typed `*CompileError` (D3); NUL bytes in the pattern are legal (D2). PCRE2 also parses Perl inline modifiers (`(?i)`, `(?i-m)`, `(*UTF)`) natively, so flags can live in the pattern. |
| `MustCompile(pattern string, flag int) Regexp` | same | Panics with the `*CompileError` (D3). |
| `CompileParse(ptr string) (Regexp, error)` | same | Lenient `ParseFlags` semantics kept, including the `(?R)` mangling caveat; the error keeps the generic `can't compile/study pcre regexp: ...` prefix and now wraps the `*CompileError` (D13). Prefer the new `CompileParseStrict`: Perl-faithful parsing and the `*CompileError` returned unwrapped. |
| `CompileJIT(pattern string, flagsC, flagsS int) (Regexp, error)` | same | `flagsS` must include `JIT_COMPLETE` (v1 name `STUDY_JIT_COMPILE` still works); the guard's error text changed. On a libpcre2 built without JIT it now returns an error where v1 silently matched JIT-less; probe with the new `JITAvailable()`. |
| `CompileParseJIT(ptr string, flags int) (Regexp, error)` | same | Combines the `CompileParse` and `CompileJIT` rows; the error wraps the underlying compile, flag or study error (D13). |
| `MustCompileParse(pattern string) Regexp` | same | Panics on failure, as v1. |
| `MustCompileJIT(pattern string, flagsC, flagsS int) Regexp` | same | See `CompileJIT`. |
| `MustCompileParseJIT(pattern string, flags int) Regexp` | same | See `CompileParseJIT`. |
| `ParseFlags(ptr string) (string, int)` | same | Same lenient algorithm and letter map (`i m s U J x X D u`). `u` now yields `UTF\|UCP` (identical meaning to v1's `UTF8\|UCP`); `X` yields the no-op `EXTRA` (D8). The new `ParseFlagsStrict` leaves non-flag groups such as `(?R)` to the engine. |
| `Config(f int) string` | same | D10: numeric answers are uniform `uint32`; `CONFIG_VERSION`, `CONFIG_UNICODE_VERSION`, `CONFIG_JITTARGET` return text; unknown keys return `""`. Several key constants were renamed - see the constants tables. |
| `ConfigAll() string` | same | D10: lists PCRE2's key set; names and value encodings differ from v1's PCRE1 set. |

### Regexp methods

| v1 | v2 | Differences |
|---|---|---|
| `Study(flags int) error` | same | D6: `Study(0)` is a successful no-op; JIT flags run `pcre2_jit_compile`. Errors on a JIT-less libpcre2 instead of silently doing nothing. Same in-place mutation contract: must complete before the Regexp is shared. |
| `Groups() int` | same | Same. |
| `CaptureNames() []CaptureName` | same | Same (PCRE2 kept the name-table layout); with `DUPNAMES` repeated names appear, as in v1. |
| `MatchWFlags(subject []byte, flags int) bool` | same | Same answer; internally recycles a pooled Matcher, so no per-call C allocation; match errors never panic (D1). |
| `MatchStringWFlags(subject string, flags int) bool` | same | As `MatchWFlags`. |
| `NewMatcher(subject []byte, flags int) *Matcher` | same | Same; the Matcher now owns a C match-data block, released by GC or the new `Matcher.Free` (D9). |
| `NewMatcherString(subject string, flags int) *Matcher` | same | As `NewMatcher`. |
| `FindIndex(bytes []byte, flags int) []int` | same | Same. |
| `FindString(s string, flags int) string` | same | Same, including the caveat that `""` means both "no match" and a valid empty-width match. |
| `FindAllIndex(bytes []byte, flags int) [][]int` | same | D4 boundary-correct iteration; D5 empty-match advance; D12 Perl global-match protocol. |
| `ReplaceAll(bytes, repl []byte, flags int) []byte` | same | D4/D5. The replacement stays literal; for `$1`/`${name}` templates use the new `ReplaceAllTemplate`. |
| `ReplaceAllString(subj, repl string, flags int) string` | same | As `ReplaceAll`. |

### Matcher methods

| v1 | v2 | Differences |
|---|---|---|
| `Exec(subject []byte, flags int) int` | same | Same contract; the raw return codes are PCRE2's (renumbered - see the error constants). Panic message on an uninitialized Matcher reworded. |
| `ExecString(subject string, flags int) int` | same | As `Exec`. |
| `MatchWFlags(subject []byte, flags int) bool` | same | D1: any negative code except no-match/partial lands in `Matcher.Error` as `*MatchError`; v1 panicked on several of them. |
| `MatchStringWFlags(subject string, flags int) bool` | same | As `MatchWFlags`. |
| `Reset(re Regexp, subject []byte, flags int)` | same | Same; panic text on an uninitialized Regexp reworded. |
| `ResetString(re Regexp, subject string, flags int)` | same | As `Reset`. |
| `Group(group int) []byte` | same | Same: nil for a non-participating group, index panic when group > Groups. A nil subject no longer overflows the stack (v1 bug: `Group` and `GroupString` deferred to each other when both subject fields were empty). |
| `GroupString(group int) string` | same | Same. |
| `GroupIndices(group int) []int` | same | Same. |
| `Present(group int) bool` | same | Same. |
| `Index() []int` | same | Same. |
| `Extract() [][]byte` | same | Same: `[0]` is the whole subject, unset groups nil. |
| `ExtractString() []string` | same | Same. |
| `Named(group string) ([]byte, error)` | same | D11: under `DUPNAMES` a non-unique name fails with `ErrNonUniqueName`. Unknown-name error text gained a `pcre:` prefix. |
| `NamedString(group string) (string, error)` | same | As `Named`. |
| `NamedPresent(group string) bool` | same | Same caveat kept: false both for a non-participating group and for an unknown name. |

### Matcher exported fields

| Field | Differences |
|---|---|
| `Groups int` | Same. |
| `Matches bool` | Same. |
| `Partial bool` | Same meaning; the underlying C code changed from -12 to -2 (see `ERROR_PARTIAL`). |
| `Error error` | Now a typed `*MatchError{Code, Message}` (D1); v1 stored a formatted string and panicked on several codes. |
| `SubjectS string` | Same, including the fallback rules between the string and []byte accessor paths. |
| `SubjectB []byte` | Same. |

### Types

| v1 | v2 | Differences |
|---|---|---|
| `Regexp` | same | Still opaque and freely copyable; all copies share one compiled pattern, so the new `Free` (D9) invalidates every copy. Concurrency contract unchanged. |
| `Matcher` | same | Fields above; adds `Free` (D9); still single-goroutine. |
| `CaptureName{Name string; Index int}` | same | Unchanged. |
| - | `CompileError{Pattern, Message, Offset}` | New: returned by the Compile family (D3). |
| - | `MatchError{Code, Message}` | New: stored in `Matcher.Error` (D1). |
| - | `ErrNonUniqueName` | New: wrapped by `Named*` errors under `DUPNAMES` (D11). |

### Constants: unchanged (same name, same meaning; numeric values differ)

- Compile options: `ANCHORED`, `CASELESS`, `DOLLAR_ENDONLY`, `DOTALL`,
  `DUPNAMES`, `EXTENDED`, `FIRSTLINE`, `MULTILINE`, `NO_AUTO_CAPTURE`,
  `UNGREEDY`, `UCP`. (`ANCHORED` is still also valid at match time.)
- Match options: `NOTBOL`, `NOTEOL`, `NOTEMPTY`, `NOTEMPTY_ATSTART`,
  `PARTIAL_SOFT`, `PARTIAL_HARD`.
- Config keys: `CONFIG_JIT`, `CONFIG_JITTARGET`. `CONFIG_NEWLINE` and
  `CONFIG_BSR` also keep their names but return PCRE2's value encodings,
  not PCRE1's (D10).
- Error codes: `ERROR_NOMATCH` (still -1, the only stable value),
  `ERROR_BADOPTION`, `ERROR_BADMAGIC`, `ERROR_NOMEMORY`,
  `ERROR_NOSUBSTRING`, `ERROR_MATCHLIMIT`, `ERROR_CALLOUT`,
  `ERROR_INTERNAL`, `ERROR_JIT_STACKLIMIT`.

### Constants: renamed, v1 name kept as an alias

| v1 name | Canonical v2 name |
|---|---|
| `UTF8` | `UTF` |
| `NO_UTF8_CHECK` | `NO_UTF_CHECK` |
| `STUDY_JIT_COMPILE` | `JIT_COMPLETE` |
| `STUDY_JIT_PARTIAL_SOFT_COMPILE` | `JIT_PARTIAL_SOFT` |
| `STUDY_JIT_PARTIAL_HARD_COMPILE` | `JIT_PARTIAL_HARD` |
| `ERROR_RECURSIONLIMIT` | `ERROR_DEPTHLIMIT` (PCRE2 keeps the old name as an obsolete alias) |
| `CONFIG_STACKRECURSE` | none (obsolete PCRE2 key, always answers 0) |

### Constants: same name with a trap, or renamed without an alias

| v1 | v2 | What changed |
|---|---|---|
| `EXTRA` | `EXTRA` | Now literally 0 (D8): PCRE2 is strict by default. Accepted and ignored. |
| `JAVASCRIPT_COMPAT` | `JAVASCRIPT_COMPAT` | Now defined as `ALT_BSUX\|MATCH_UNSET_BACKREF` (D8), the two PCRE2 flags that reproduce the PCRE1 behavior. |
| `NO_START_OPTIMIZE` | `NO_START_OPTIMIZE` | v1 accepted it at match time; PCRE2 makes it compile-only. Move it to the Compile flags; pcre2_match rejects unknown option bits. |
| `ERROR_PARTIAL` | `ERROR_PARTIAL` | Value changed -12 -> -2. In PCRE1, -2 meant `ERROR_NULL`: any persisted -2 silently changes meaning. |
| `ERROR_NULL` | `ERROR_NULL` | Value changed -2 -> -51 (see the trap above). |
| `CONFIG_LINK_SIZE` | `CONFIG_LINKSIZE` | Renamed, no alias: update call sites. |
| `CONFIG_MATCH_LIMIT` | `CONFIG_MATCHLIMIT` | Renamed, no alias: update call sites. |
| `CONFIG_MATCH_LIMIT_RECURSION` | `CONFIG_DEPTHLIMIT` | PCRE2 renamed the concept ("recursion limit" -> "depth limit"). The obsolete `CONFIG_RECURSIONLIMIT` alias is also exported. |
| `ERROR_BADUTF8_OFFSET` | `ERROR_BADUTFOFFSET` | Renamed, no alias: update call sites. |

### Constants: removed, with workaround

| v1 | Workaround in v2 |
|---|---|
| `NEWLINE_CR`, `NEWLINE_LF`, `NEWLINE_CRLF`, `NEWLINE_ANYCRLF`, `NEWLINE_ANY` | D7: start the pattern with `(*CR)`, `(*LF)`, `(*CRLF)`, `(*ANYCRLF)`, `(*ANY)`. |
| `BSR_ANYCRLF`, `BSR_UNICODE` | D7: start the pattern with `(*BSR_ANYCRLF)` / `(*BSR_UNICODE)`. |
| `CONFIG_UTF8`, `CONFIG_UTF16`, `CONFIG_UTF32`, `CONFIG_UNICODE_PROPERTIES` | `CONFIG_UNICODE` (PCRE2 Unicode support, properties included, is all-or-nothing) plus `CONFIG_COMPILED_WIDTHS` (bitmap: 1=8bit, 2=16bit, 4=32bit). |
| `CONFIG_POSIX_MALLOC_THRESHOLD` | None: PCRE2 has no POSIX-wrapper malloc threshold. |
| `ERROR_BADUTF8` | `MatchError.Code` carries PCRE2's specific per-problem UTF-8 code instead of one blanket value. |
| `ERROR_BADPARTIAL` | None: PCRE2 lifted the restriction (every pattern supports partial matching). |
| `ERROR_UNKNOWN_OPCODE`, `ERROR_UNKNOWN_NODE`, `ERROR_BADCOUNT` | None: these conditions cannot occur through this API. v1 panicked on them (D1). |

v2 additionally exports PCRE2-only constants (compile options such as
`LITERAL` and `ENDANCHORED`, the `SUBSTITUTE_*` options, new error codes,
new config keys, and the whole `INFO_*` pattern-info family); those are
listed in consts.go and are not part of the v1 surface.

## Regex dialect changes (PCRE 8.45 -> PCRE2 10.x)

The C engine's regex dialect itself moved between PCRE 8.45 and PCRE2.
The same Go call with the same pattern and subject can therefore change
behavior even where the binding is fully compatible. Differences known to
be user-visible through this API:

- **`\8` and `\9` are always backreferences.** PCRE1 treated them as
  literal "8"/"9" when the pattern had fewer than 8/9 groups; PCRE2
  rejects the pattern (or resolves the reference if the groups exist).
  A sequence like `\81` is a backreference too, never "8" + "1".
- **Bare `\x` and invalid `\x{...}` are compile errors** (PCRE2 10.45+).
  PCRE1 accepted `\x` without hex digits as NUL.
- **Bad quantifiers are compile errors.** `{3,1}` (min > max) and a
  quantifier with nothing to repeat (for example `*a`) fail to compile;
  PCRE1 was tolerant of some of these forms.
- **`(?|...)` branch-reset groups reject same-number-different-name.**
  `(?|(?<a>A)|(?<b>B))` compiles in PCRE1 and is a compile error in PCRE2.
- **Group name length limit rose from 32 to 128 characters.** Names that
  failed to compile in v1 as too long may compile in v2. Character rules
  are unchanged (letters, digits, underscore; no leading digit).
- **`\K` is rejected inside lookarounds** (PCRE2 10.38+ default). PCRE1
  accepted it there. On libpcre2 10.34 through 10.37 such patterns still
  compile; a match whose `\K` moved the start after its own end or before
  the search offset then ends the `FindAllIndex`/`ReplaceAll` iteration,
  so the `ReplaceAll` result equals v1's.
- **Caseless matching unifies the Lu/Ll/Lt properties** (PCRE2 10.45+,
  matching Perl): `\p{Lu}` with `CASELESS` matches lowercase letters too.
- **`[[:space:]]` includes vertical tab** (PCRE2 follows Perl's change);
  PCRE1's POSIX space class excluded VT.
- **`\N{U+hhhh}` is supported in UTF mode.** PCRE1 rejected it outright
  at compile time (its error message lumps it in with the unsupported
  `\N{name}` form). Named forms like `\N{LATIN SMALL LETTER A}` remain
  compile errors in both.
- **Perl 5.14+ inline modifiers compile.** `(?n)` (no auto capture),
  `(?^i)` (flag reset) and `(?xx)` are valid in PCRE2; PCRE1 failed to
  compile them with "unrecognized character after (?".
- **Octal escape edge cases differ.** PCRE2 adds stricter, configurable
  handling around `\0` and the octal/backreference ambiguity.
- **Auto-possessification and start-of-match optimizations differ**, which
  can change match counts for pathological patterns and the point at which
  `MATCHLIMIT`/`DEPTHLIMIT` errors fire, though not ordinary results.
- **Backtracking limits were renamed and extended.** PCRE1's
  "match limit recursion" is PCRE2's "depth limit"; PCRE2 adds a heap
  limit (default 20 MB per match) that PCRE1 did not have, so extreme
  patterns can now fail with `ERROR_HEAPLIMIT`.
- **Compile error messages were all reworded** (D3), for example
  "missing )" became "missing closing parenthesis" and "nothing to
  repeat" became "quantifier does not follow a repeatable item".

These entries are verified by the differential suite in `compat/`, which
runs a shared corpus of patterns through v1 and v2 and classifies every
observed difference.
