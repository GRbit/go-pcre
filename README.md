# go-pcre/v2

[![Go Reference](https://pkg.go.dev/badge/github.com/GRbit/go-pcre/v2.svg)](https://pkg.go.dev/github.com/GRbit/go-pcre/v2)
[![License](https://img.shields.io/github/license/GRbit/go-pcre)](LICENSE)

Perl-Compatible Regular Expressions for Go via **PCRE2** (10.x), with JIT
compilation and true parallel matching.

This is v2 of [github.com/GRbit/go-pcre](https://github.com/GRbit/go-pcre).
The binding was rewritten on top of PCRE2 (`libpcre2-8`) and no longer uses
the legacy PCRE 8.x library that v1 links, which current Linux
distributions do not package any more. The v1 `Regexp`/`Matcher` API is
kept, so existing code migrates by changing the import path.

## Migrating from v1

1. Install `libpcre2-dev` (v1 needed `libpcre3-dev` or a hand-built PCRE 8.45).
2. Change the import path to `github.com/GRbit/go-pcre/v2`; the package
   name stays `pcre`.
3. Read [MIGRATION.md](MIGRATION.md). It maps every exported v1 identifier
   to its v2 replacement and lists the intentional behavior differences
   (typed errors instead of panics, boundary-correct `FindAllIndex` and
   `ReplaceAll`, no `NEWLINE_*`/`BSR_*` flags, and so on) together with
   the regex dialect changes between PCRE 8.45 and PCRE2 10.x.

v1 stays on the [`pcre8.x`](https://github.com/GRbit/go-pcre/tree/pcre8.x)
branch. [ARCHITECTURE.md](ARCHITECTURE.md) explains how the binding works.

## Installation

PCRE2 ships as a standard package on every current distribution, so there
is no need to build PCRE by hand any more:

```bash
sudo apt-get install libpcre2-dev   # Debian/Ubuntu
go get github.com/GRbit/go-pcre/v2
```

Requires Go >= 1.24 and `libpcre2-8` >= 10.34 (Debian 11 / Ubuntu 20.04 or
newer). The package fails at build time on older versions rather than
degrading silently. Distribution packages ship with JIT enabled; verify at
runtime with `pcre.JITAvailable()` and per pattern with
`re.JITCompiled()`.

## Usage

```go
import "github.com/GRbit/go-pcre/v2" // package name is "pcre"

re := pcre.MustCompileJIT(`(?<user>\w+)@(?<host>\w+)`, 0, pcre.STUDY_JIT_COMPILE)

m := re.NewMatcherString("bob@example.com", 0)
if m.Matches {
    user, _ := m.NamedString("user") // "bob"
    _ = user
}

out, _ := re.ReplaceAllTemplateString("bob@example", "${host}/${user}", 0) // "example/bob"
```

Flags can be passed as constants (`pcre.CASELESS|pcre.MULTILINE`) or
written inside the pattern: PCRE2 natively parses Perl's inline modifiers
(`(?i)`, `(?i-m)`, `(?i:...)`, `(*UTF)`, `(*UCP)`), which is the most
Perl-compatible route. The `ParseFlags`/`CompileParse` family exists for
v1 compatibility; prefer `ParseFlagsStrict`/`CompileParseStrict` for new
code (they leave constructs like `(?R)` to the engine instead of mangling
them).

## Concurrency

A `Regexp`, once fully constructed (compiled and, if used, JIT-compiled),
is safe for concurrent matching from multiple goroutines. A `Matcher` is
stateful: use one per goroutine. This is exactly PCRE2's own threading
contract, validated under `-race`.

## Performance

Medians of five `go test -bench . -benchmem` runs on one x86-64 machine in
one session (Go 1.27; PCRE2 10.46 and PCRE 8.45, both with JIT). "Exec"
uses a 350-character real-world date-check pattern with backreferences on
a 10-byte subject; the exec benchmarks allocate nothing.

| benchmark | v2 (PCRE2) | v1 (PCRE 8.45) | Go `regexp` |
|---|---|---|---|
| Exec, JIT | 62 ns/op | 62 ns/op | n/a (backreferences) |
| Exec, interpreter | 228 ns/op | 201 ns/op | n/a (backreferences) |
| ReplaceAll, 20-byte subject, 4 matches | 296 ns/op, 1 alloc | 325 ns/op, 4 allocs | 268 ns/op, 5 allocs |
| ReplaceAllString, same input | 323 ns/op, 2 allocs | 347 ns/op, 5 allocs | 276 ns/op, 5 allocs |
| ReplaceAllString, 12 KB subject, 1000 matches | 79 us/op, 3 allocs | 75 us/op, 5 allocs | 133 us/op, 18 allocs |
| ReplaceAllTemplate (`$1`/`${name}`) | 286 ns/op, 2 allocs | n/a | n/a |

JIT matching is 3.7x faster than the interpreter on this pattern and
equally fast in v1 and v2; the interpreter is about 13% slower in v2.
Every call pays a fixed cgo round trip, which is why the standard library
wins on a 20-byte subject and loses by 1.7x on a 12 KB one. Absolute
numbers vary with the machine; the ratios hold. For an exhaustive
cross-library study see https://zherczeg.github.io/sljit/regex_perf.html

## Building your software

Since this package uses `cgo` it builds dynamically linked. For a static
binary:

```bash
go build -ldflags="-extldflags=-static"
```

More details [here](https://www.arp242.net/static-go.html).

## CI

- Needs `libpcre2-dev` installed (`apt-get install libpcre2-dev`).
- Run `go vet ./...`, `go test ./...`, `go test -race ./...`; for changes
  touching cgo memory, also `GOEXPERIMENT=cgocheck2 go test -race ./...`.
- Benchmarks (`go test -bench . -run '^$'`) are a manual job: they are
  compared against v1 on the same machine, not against CI noise.

## LICENSE

Same BSD-style license as v1 (see LICENSE). v1 descends from
[glenn-brown/golang-pkg-pcre](https://github.com/glenn-brown/golang-pkg-pcre);
v2 is a fresh PCRE2 binding that keeps the v1 API surface.
