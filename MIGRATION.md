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

Each of these is pinned by a test in the v2 suite.

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
   differs from PCRE1's. Match on the type/offset, not the text.
4. **Iteration is boundary-correct.** `FindAllIndex` and `ReplaceAll`
   drive PCRE2's native start offset instead of re-slicing the subject, so
   `^`, `\b`/`\B` and lookbehind see the true context at every iteration
   boundary. Examples that change vs v1: `\Biss` on `"Mississippi"` now
   finds both `[1,4]` and `[4,7]`; `(?<=a)a` on `"aaa"` finds two matches;
   `^.` on `"abc"` finds only `[0,1]`.
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
    `errors.Is`); v1 reported a generic unknown-name error.

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
