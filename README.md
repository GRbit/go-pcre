# go-pcre/v2

[![License](https://img.shields.io/github/license/GRbit/go-pcre)](LICENSE)

Perl-Compatible Regular Expressions for Go via **PCRE2** (10.x), with JIT
compilation. This is v2 of [github.com/GRbit/go-pcre](https://github.com/GRbit/go-pcre),
porting the same `Regexp`/`Matcher` API from the legacy PCRE 8.x library to
PCRE2. v1 users migrate by changing the import path; the small list of
intentional behavior differences will be documented in the migration guide
(placeholder below).

**Status: under development.** The port is being built phase by phase; the
v1 test suite is its conformance oracle.

## Installation

PCRE2 ships as a standard package on every current distribution - no more
building PCRE by hand:

```bash
sudo apt-get install libpcre2-dev   # Debian/Ubuntu
go get github.com/GRbit/go-pcre/v2
```

Requires `libpcre2-8` >= 10.34 (Debian 11 / Ubuntu 20.04 era or newer). The
package fails at build time on older versions rather than degrading
silently. JIT is enabled in distribution packages by default; verify at
runtime with the JIT detection API (Phase 3).

## Usage

```go
import "github.com/GRbit/go-pcre/v2"
```

## Migrating from v1

Placeholder - the migration guide lands in Phase 6. Headline divergences
already decided: embedded NUL bytes in patterns are legal; match errors are
returned, never panicked; iteration is boundary-correct for `^`/`\b`/
lookbehind and UTF-aware on empty-match advance; `NEWLINE_*`/`BSR_*` flag
constants are absent (use in-pattern `(*CRLF)` etc.); explicit
`Free()`/`Close()` is available with GC cleanup as backstop.

## LICENSE

Same BSD-style license as v1 (see LICENSE). v1 descends from
[glenn-brown/golang-pkg-pcre](https://github.com/glenn-brown/golang-pkg-pcre);
v2 is a fresh PCRE2 binding that keeps the v1 API surface.
