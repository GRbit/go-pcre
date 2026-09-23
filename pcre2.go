// Package pcre provides access to the Perl Compatible Regular Expression
// library, PCRE2 (10.x).
//
// This is v2 of github.com/GRbit/go-pcre, a port of the v1 API from the
// legacy PCRE 8.x library to PCRE2. The Regexp/Matcher surface is
// v1-compatible; intentional divergences are listed in the migration guide.
//
// Compilation of regular expressions using Compile or MustCompile is
// slightly expensive, so these objects should be kept and reused, instead
// of compiling them from scratch for each matching attempt.
//
// Concurrency: a Regexp, once fully constructed, is safe for concurrent
// matching from multiple goroutines. "Fully constructed" means Compile has
// returned and, if you use it, JIT compilation has completed. A Matcher is
// stateful and must only be used by one goroutine at a time. Free must not
// be called while other goroutines use the Regexp.
//
// Match errors: the stateless helpers (MatchWFlags, Find*, ReplaceAll)
// treat a match-time error (invalid UTF subject, match or depth limit) as
// no match, exactly as v1 did. To observe the error, match through a
// Matcher and read Matcher.Error.
//
// Requirements: libpcre2-8 >= 10.34 (Debian/Ubuntu: apt install
// libpcre2-dev). Features that need a newer libpcre2 are gated to fail at
// build time rather than silently degrade.
package pcre

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#if PCRE2_MAJOR < 10 || (PCRE2_MAJOR == 10 && PCRE2_MINOR < 34)
#error "github.com/GRbit/go-pcre/v2 requires libpcre2-8 >= 10.34"
#endif
*/
import "C"

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"
)

// codesFreed counts pcre2_code_free calls; it exists for tests to observe
// that cleanups actually release compiled patterns (v1's studiesFreed
// pattern).
var codesFreed atomic.Uint64

// codeHandle owns a compiled pattern: the pcre2_code block, including any
// JIT data, which only pcre2_code_free can release. All copies of a Regexp
// share one handle.
type codeHandle = handle[*C.pcre2_code]

func newCodeHandle(p *C.pcre2_code) *codeHandle {
	return newHandle(p, freeCode)
}

func freeCode(p *C.pcre2_code) {
	C.pcre2_code_free(p)
	codesFreed.Add(1)
}

// handleName names the Go-level owner of a C block in use-after-free
// panics: users know Regexp and Matcher, not pcre2_code and match_data.
func handleName[P comparable]() string {
	var nilP P
	switch any(nilP).(type) {
	case *C.pcre2_code:
		return "Regexp"
	case *C.pcre2_match_data:
		return "Matcher"
	}

	return "handle"
}

// CompileError is returned by Compile when PCRE2 rejects a pattern.
type CompileError struct {
	Pattern string // the rejected pattern
	Message string // PCRE2's error message
	Offset  int    // byte offset in Pattern where the error was detected
}

func (e *CompileError) Error() string {
	return fmt.Sprintf("%s (%d): %s", e.Pattern, e.Offset, e.Message)
}

// errorMessage renders a PCRE2 error code (compile or match) as text.
func errorMessage(code C.int) string {
	var buf [256]C.PCRE2_UCHAR
	n := C.pcre2_get_error_message(code, &buf[0], C.PCRE2_SIZE(len(buf)))
	if n < 0 {
		return fmt.Sprintf("unknown PCRE2 error (code %d)", int(code))
	}

	return C.GoStringN((*C.char)(unsafe.Pointer(&buf[0])), n)
}

// cptr returns the pointer through which C reads b. An empty slice has no
// addressable element, so a one-byte stand-in is used; the true length is
// always passed separately.
func cptr(b []byte) *C.PCRE2_UCHAR {
	if len(b) == 0 {
		b = []byte{0}
	}

	return (*C.PCRE2_UCHAR)(unsafe.Pointer(&b[0]))
}

// Regexp is a reference to a compiled regular expression.
// Use Compile or MustCompile to create such objects.
// Once fully constructed it is safe for concurrent use by multiple
// goroutines; see the package comment.
type Regexp struct {
	code *codeHandle

	// matchers recycles Matchers (and their C match_data blocks) for the
	// stateless helper APIs (MatchWFlags, Find*, ReplaceAll), which would
	// otherwise create and abandon one pcre2_match_data per call. Shared by
	// all copies of the Regexp, like code. Entries reference code back; the
	// cycle is collected as a unit and the match-data cleanups still run.
	matchers *sync.Pool

	// Facts queried once at compile time (pcre2_pattern_info). The bools
	// steer the bump-along advance of the global-match protocol; groups
	// sizes every Matcher bound to the pattern.
	groups      int
	utf         bool // compiled with PCRE2_UTF: advance whole characters
	crlfNewline bool // newline convention includes CRLF: skip it atomically
}

// Compile the pattern. If an error occurs, the second return value is
// non-nil, and is a *CompileError carrying PCRE2's message and the byte
// offset of the problem inside the pattern.
//
// Flags can also be written inside the pattern itself: PCRE2 natively
// parses Perl's inline modifiers - "(?i)", "(?m)", "(?s)", "(?x)"/"(?xx)",
// "(?n)", "(?U)", "(?J)", negation "(?i-m)", reset "(?^i)", scoped groups
// "(?i:...)" - plus the start-of-pattern verbs "(*UTF)" and "(*UCP)" that
// replace the UTF/UCP flags. Modifiers are handled with Perl's placement
// rules and Perl's errors for unknown letters, so plain Compile with
// inline modifiers is the most Perl-compatible way to set flags; the
// ParseFlags family exists for v1 compatibility and convenience.
//
// Unlike v1, patterns may contain NUL bytes: PCRE2 receives the pattern
// with an explicit length (intentional v2 divergence).
func Compile(pattern string, flags int) (Regexp, error) {
	var errCode C.int
	var errOffset C.PCRE2_SIZE
	p := C.pcre2_compile(
		cptr([]byte(pattern)),
		C.PCRE2_SIZE(len(pattern)),
		C.uint32_t(flags),
		&errCode,
		&errOffset,
		nil, // default compile context
	)
	if p == nil {
		return Regexp{}, &CompileError{
			Pattern: pattern,
			Message: errorMessage(errCode),
			Offset:  int(errOffset),
		}
	}

	nl := info32(p, C.PCRE2_INFO_NEWLINE)

	return Regexp{
		code:     newCodeHandle(p),
		matchers: new(sync.Pool),
		groups:   int(info32(p, C.PCRE2_INFO_CAPTURECOUNT)),
		utf:      info32(p, C.PCRE2_INFO_ALLOPTIONS)&C.PCRE2_UTF != 0,
		crlfNewline: nl == C.PCRE2_NEWLINE_CRLF ||
			nl == C.PCRE2_NEWLINE_ANY || nl == C.PCRE2_NEWLINE_ANYCRLF,
	}, nil
}

// MustCompile is same as Compile but if compilation fails, panic.
func MustCompile(pattern string, flags int) (re Regexp) {
	re, err := Compile(pattern, flags)
	if err != nil {
		panic(err)
	}

	return
}

// Groups returns the number of capture groups in the pattern.
func (re Regexp) Groups() int {
	re.code.check() // a freed or zero Regexp panics here as everywhere

	return re.groups
}

// Free releases the compiled pattern immediately instead of waiting for
// garbage collection. It is idempotent. All copies of this Regexp become
// unusable; using one afterwards panics.
func (re Regexp) Free() {
	if re.code != nil {
		re.code.Free()
	}
}
