go-pcre
===============

This package provides Perl-Compatible RegularExpression
support in Go using `libpcre` or `libpcre++`.

The origin of this package is [glenn-brown pcre](https://github.com/glenn-brown/golang-pkg-pcre)
but across other forks, this one has JIT compilation available, which makes it much faster.
You can check out [benchmarks game](https://benchmarksgame-team.pages.debian.net/benchmarksgame/performance/regexredux.html)
to see the difference.

| Go library | Time (lower is better) |
| ---------- | ---------------------- |
| This one | 3.85 seconds |
| [mdellandrea](https://github.com/mdellandrea/golang-pkg-pcre) (also glenn-brown fork)  | 14.48 seconds |
| standard one |  27.87 seconds |

As you can see, this library is almost an order
of magnitude faster than standard one and
3-4 times faster tahn pcre without JIT compilation.

## Interface / API

API this library provides is a plain copy of C library API.
Which may look really ugly to Go programmers.
At least, it looks ugly to me, I don't think it's very
convenient to set binary flags to use your regexp.

I want to refactor this library and make v2 version which will
have API more like a standard library. If you are interested
in such library, hit the star button. The more stars I see,
the closer I am to implementing this idea.

## Documentation

Use [godoc](https://godoc.org/github.com/GRbit/go-pcre).

## Installation

1. install `libpcre3-dev` or `libpcre++-dev`

2. go get

```bash
sudo apt-get install libpcre3-dev
go get github.com/GRbit/go-pcre/
```

## Usage

Go programs that depend on this package should import this package as
follows to allow automatic downloading:

```go
import (
  "github.com/GRbit/go-pcre/"
)
```

## Building your software

Since this package use `cgo` it will build dynamically linked.
If you plan to use this everywhere without `libpcre` dependency,
you should build it statically linked. You can build your software
with the following options:
```bash
go build -ldflags="-extldflags=-static"
```
More details on this [here](https://www.arp242.net/static-go.html)

## Performance

Brief performance comparison across other Go libraries is in the beginning
of the README, but if you are curious what regex library is the fastest here is
an exhaustive research of the question:
https://zherczeg.github.io/sljit/regex_perf.html

The answer is: it depends. But in most cases, it's RE2 or PCRE-JIT.
RE2 tends to utilize multi-core systems better,
while PCRE-JIT is better at using one CPU core for almost all use cases.

## LICENSE

This is a fork of [hobeone pcre](https://github.com/hobeone/go-pcre),
which is fork of [mathpl pcre](https://github.com/mathpl/golang-pkg-pcre),
which is a fork of [glenn-brown pcre](https://github.com/glenn-brown/golang-pkg-pcre).
The original package hasn't been updated for several years.
But it is still being used in some software, despite its lack
of JIT compiling, which gives huge speed-up to regexps.
If you somehow can send a message to the original project owner,
please inform him about this situation. Maybe he would like to
transfer control over the repository to a maintainer who will
have time to review pull requests.
