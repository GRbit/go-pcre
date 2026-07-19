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
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

// libJITSupported reports whether the linked libpcre2-8 was built with JIT
// support. Phase 3 builds the public JITAvailable on top of it.
func libJITSupported() bool {
	var jit C.uint32_t
	C.pcre2_config(C.PCRE2_CONFIG_JIT, unsafe.Pointer(&jit))

	return jit != 0
}

// codesFreed counts pcre2_code_free calls; it exists for tests to observe
// that cleanups actually release compiled patterns (v1's studiesFreed
// pattern).
var codesFreed atomic.Uint64

// codeHandle owns a compiled pattern. The pcre2_code block (including any
// JIT data) is C memory that only pcre2_code_free can release, so it is
// held behind this handle and freed either explicitly via Free or by a GC
// cleanup once the last Regexp copy referring to it becomes unreachable.
type codeHandle struct {
	p       *C.pcre2_code
	cleanup runtime.Cleanup
	free    sync.Once
}

func newCodeHandle(p *C.pcre2_code) *codeHandle {
	h := &codeHandle{p: p}
	h.cleanup = runtime.AddCleanup(h, freeCode, p)

	return h
}

func freeCode(p *C.pcre2_code) {
	C.pcre2_code_free(p)
	codesFreed.Add(1)
}

// Free releases the compiled pattern immediately. It is idempotent. Calling
// it concurrently with, or before, uses of any Regexp copy sharing this
// handle is a data race (same contract as matching: see the package
// comment).
func (h *codeHandle) Free() {
	h.free.Do(func() {
		h.cleanup.Stop()
		freeCode(h.p)
		h.p = nil
	})
}

// ptr returns the code pointer for a C call. Every caller must
// runtime.KeepAlive(h) after the C call returns, so the cleanup cannot fire
// while C still uses the pointer.
func (h *codeHandle) ptr() *C.pcre2_code {
	if h == nil || h.p == nil {
		panic("pcre: use of uninitialized or freed Regexp")
	}

	return h.p
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
}

// Compile the pattern. If an error occurs, the second return value is
// non-nil, and is a *CompileError carrying PCRE2's message and the byte
// offset of the problem inside the pattern.
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

	return Regexp{code: newCodeHandle(p)}, nil
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
	var count C.uint32_t
	C.pcre2_pattern_info(re.code.ptr(), C.PCRE2_INFO_CAPTURECOUNT, unsafe.Pointer(&count))
	runtime.KeepAlive(re.code)

	return int(count)
}

// Free releases the compiled pattern immediately instead of waiting for
// garbage collection. It is idempotent. All copies of this Regexp become
// unusable; using one afterwards panics.
func (re Regexp) Free() {
	if re.code != nil {
		re.code.Free()
	}
}
