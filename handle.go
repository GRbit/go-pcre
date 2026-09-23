package pcre

import (
	"runtime"
	"sync"
)

// handle owns one block of C memory (a pcre2_code or a pcre2_match_data)
// that only its own free function can release. The block is freed either
// explicitly via Free or by a GC cleanup once the handle becomes
// unreachable; the cleanup is the backstop, not the API.
//
// The pointer is not handed out: every C call goes through use, which
// keeps the handle reachable until the call returns. Without that a
// cleanup could free the block mid-call once the owning Go object is no
// longer referenced (a latent bug in prior-art PCRE2 wrappers). The single
// exception is Matcher.exec (the hot path), which calls ptr and KeepAlive
// by hand and says so.
//
// P is the C pointer type (*C.pcre2_code, *C.pcre2_match_data): the C
// structs themselves are incomplete types and cannot be type arguments.
type handle[P comparable] struct {
	p       P
	freeFn  func(P)
	cleanup runtime.Cleanup
	free    sync.Once
}

func newHandle[P comparable](p P, freeFn func(P)) *handle[P] {
	h := &handle[P]{p: p, freeFn: freeFn}
	h.cleanup = runtime.AddCleanup(h, freeFn, p)

	return h
}

// Free releases the block immediately. It is idempotent. Calling it
// concurrently with, or before, a use of the same handle is a data race
// (same contract as matching: see the package comment).
func (h *handle[P]) Free() {
	h.free.Do(func() {
		h.cleanup.Stop()
		h.freeFn(h.p)
		var nilP P
		h.p = nilP
	})
}

func (h *handle[P]) ptr() P {
	var nilP P
	if h == nil || h.p == nilP {
		panic(unusable[P]())
	}

	return h.p
}

// unusable builds the use-after-free message. Kept out of line so the
// inlined ptr check stays a compare and branch on the hot path.
//
//go:noinline
func unusable[P comparable]() string {
	return "pcre: use of uninitialized or freed " + handleName[P]()
}

// check panics exactly as use would on a zero or freed handle, for
// methods that serve facts cached at construction without touching the
// block.
func (h *handle[P]) check() {
	h.ptr()
}

// use runs f with the block's pointer and keeps the handle alive until f
// returns. f must not retain the pointer.
func use[P comparable, R any](h *handle[P], f func(P) R) R {
	r := f(h.ptr())
	runtime.KeepAlive(h)

	return r
}
