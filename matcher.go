package pcre

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdlib.h>
#include <pcre2.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

// unset is PCRE2_UNSET, the ovector value marking a capture group that did
// not participate in the match. Offsets are unsigned (PCRE2_SIZE), so this
// must be compared with ==, never with a >= 0 style sign check.
const unset = ^C.PCRE2_SIZE(0)

// matchDatasFreed counts pcre2_match_data_free calls; it exists for tests
// to observe that cleanups actually release match data.
var matchDatasFreed atomic.Uint64

// matchData owns a pcre2_match_data block: C memory freed either explicitly
// via Free or by a GC cleanup once the owning Matcher is unreachable.
type matchData struct {
	p       *C.pcre2_match_data
	cleanup runtime.Cleanup
	free    sync.Once
}

func newMatchData(p *C.pcre2_match_data) *matchData {
	h := &matchData{p: p}
	h.cleanup = runtime.AddCleanup(h, freeMatchData, p)

	return h
}

func freeMatchData(p *C.pcre2_match_data) {
	C.pcre2_match_data_free(p)
	matchDatasFreed.Add(1)
}

// Free releases the match data immediately. It is idempotent.
func (h *matchData) Free() {
	h.free.Do(func() {
		h.cleanup.Stop()
		freeMatchData(h.p)
		h.p = nil
	})
}

// MatchError is stored in Matcher.Error when pcre2_match fails with
// anything other than "no match" (v1 panicked on some of these codes; v2
// never does: intentional divergence).
type MatchError struct {
	Code    int    // the negative PCRE2 error code
	Message string // PCRE2's rendering of the code
}

func (e *MatchError) Error() string {
	return fmt.Sprintf("pcre2_match (%d): %s", e.Code, e.Message)
}

// Matcher objects provide a place for storing match results.
// They can be created by the NewMatcher and NewMatcherString functions,
// or they can be initialized with Reset or ResetString.
// A Matcher is not safe for concurrent use: it holds the state of the last
// match. Use one Matcher per goroutine.
type Matcher struct {
	re       Regexp
	Groups   int
	md       *matchData
	ovector  []C.PCRE2_SIZE // alias of md's ovector: pairs of offsets, PCRE2_UNSET when a group is unset
	Matches  bool           // last match was successful
	Partial  bool           // was the last match a partial match?
	Error    error          // pcre2_match error from last match
	SubjectS string         // contain found subject as string
	SubjectB []byte         // contain found subject as []byte
}

// matcherFromPool returns a Matcher bound to this pattern for the
// stateless helper APIs, recycling match data via the codeHandle pool.
// Callers must return it with putMatcher and must not retain it.
func (re *Regexp) matcherFromPool() *Matcher {
	if re.code == nil {
		panic("pcre: use of uninitialized or freed Regexp")
	}
	if v := re.code.matchers.Get(); v != nil {
		return v.(*Matcher) // pool entries are always bound to re.code
	}

	m := new(Matcher)
	m.init(*re)

	return m
}

// putMatcher parks a pooled Matcher, dropping subject references so the
// pool does not pin caller memory and cannot leak stale results.
func (re *Regexp) putMatcher(m *Matcher) {
	m.Matches = false
	m.Error = nil
	m.SubjectB = nil
	m.SubjectS = ""
	re.code.matchers.Put(m)
}

// MatchWFlags tries to match the specified byte array slice to the
// pattern. Returns true if the match succeeds.
func (re *Regexp) MatchWFlags(subject []byte, flags int) bool {
	m := re.matcherFromPool()
	defer re.putMatcher(m)

	return m.matchWithOffset(subject, 0, flags)
}

// MatchStringWFlags is the same as MatchWFlags, but accept string as argument.
func (re *Regexp) MatchStringWFlags(subject string, flags int) bool {
	m := re.matcherFromPool()
	defer re.putMatcher(m)

	return m.matchWithOffset([]byte(subject), 0, flags)
}

// NewMatcher return a new matcher object, with the byte array slice as a
// subject.
func (re Regexp) NewMatcher(subject []byte, flags int) *Matcher {
	m := new(Matcher)
	m.Reset(re, subject, flags)

	return m
}

// NewMatcherString return a new matcher object, with the subject string.
func (re Regexp) NewMatcherString(subject string, flags int) *Matcher {
	m := new(Matcher)
	m.ResetString(re, subject, flags)

	return m
}

// Reset switches the matcher object to the specified pattern and subject.
func (m *Matcher) Reset(re Regexp, subject []byte, flags int) {
	if re.code == nil {
		panic("pcre: Matcher.Reset: uninitialized Regexp")
	}

	m.init(re)
	m.MatchWFlags(subject, flags)
}

// ResetString switches the matcher object to the specified pattern and
// subject string.
func (m *Matcher) ResetString(re Regexp, subject string, flags int) {
	if re.code == nil {
		panic("pcre: Matcher.ResetString: uninitialized Regexp")
	}

	m.init(re)
	m.MatchStringWFlags(subject, flags)
}

// init binds the Matcher to an initialized Regexp, creating the
// pcre2_match_data sized for the pattern's capture count. Re-binding to
// the same compiled pattern keeps the existing match data; switching
// patterns frees the old one deterministically.
func (m *Matcher) init(re Regexp) {
	m.Matches = false
	if m.re.code == re.code {
		return
	}
	if m.md != nil {
		m.md.Free()
	}

	m.re = re
	m.Groups = re.Groups()
	md := C.pcre2_match_data_create_from_pattern(re.code.ptr(), nil)
	runtime.KeepAlive(re.code)
	if md == nil {
		panic("pcre: pcre2_match_data_create_from_pattern: out of memory")
	}
	m.md = newMatchData(md)
	// Aliasing the ovector is safe: the Matcher owns the match data, so the
	// alias lives exactly as long as the C block it points into.
	m.ovector = unsafe.Slice(C.pcre2_get_ovector_pointer(md), 2*(m.Groups+1))
}

// Free releases the Matcher's match data immediately instead of waiting
// for garbage collection. It is idempotent. The Matcher is unusable
// afterwards until re-initialized via Reset/ResetString.
func (m *Matcher) Free() {
	if m.md != nil {
		m.md.Free()
	}
	*m = Matcher{}
}

// Exec tries to match the specified byte array slice to the current
// pattern. Returns the raw pcre2_match result code.
// C docs: https://www.pcre.org/current/doc/html/pcre2_match.html
func (m *Matcher) Exec(subject []byte, flags int) int {
	m.SubjectS, m.SubjectB = "", subject

	return m.exec(subject, 0, flags)
}

// ExecString is same as Exec, but accept string as argument.
func (m *Matcher) ExecString(subject string, flags int) int {
	m.SubjectS, m.SubjectB = subject, []byte(subject)

	return m.exec(m.SubjectB, 0, flags)
}

// exec runs pcre2_match over the whole subject from startOffset. The
// ovector then holds absolute subject offsets, and the pattern sees the
// true context before the offset (\b, lookbehind), which the Find/Replace
// iteration relies on.
func (m *Matcher) exec(subject []byte, startOffset, flags int) int {
	if m.md == nil {
		panic("pcre: use of uninitialized or freed Matcher")
	}

	rc := C.pcre2_match(m.re.code.ptr(), cptr(subject),
		C.PCRE2_SIZE(len(subject)), C.PCRE2_SIZE(startOffset),
		C.uint32_t(flags), m.md.p, nil)

	// Keep both C blocks alive for the duration of the pcre2_match call
	// above; without this a GC cleanup could free them mid-call if the
	// Matcher itself is no longer referenced afterwards.
	runtime.KeepAlive(m.re.code)
	runtime.KeepAlive(m.md)

	return int(rc)
}

// finish records the outcome of a pcre2_match call and reports whether it
// matched. A partial match counts as a match, as in v1. Every other
// negative code except no-match becomes a *MatchError; v1 panicked on
// several of them.
func (m *Matcher) finish(rc int) bool {
	m.Matches = rc >= 0 || rc == ERROR_PARTIAL
	m.Partial = rc == ERROR_PARTIAL
	m.Error = nil
	if rc < 0 && rc != ERROR_NOMATCH && rc != ERROR_PARTIAL {
		m.Error = &MatchError{Code: rc, Message: errorMessage(C.int(rc))}
	}

	return m.Matches
}

// matchWithOffset is the native-startoffset primitive behind the
// Find/Replace iteration: a match at offset within the full subject.
func (m *Matcher) matchWithOffset(subject []byte, offset, flags int) bool {
	m.SubjectS, m.SubjectB = "", subject

	return m.finish(m.exec(subject, offset, flags))
}

// MatchWFlags tries to match the specified byte array slice to the
// pattern. Returns true if the match succeeds.
func (m *Matcher) MatchWFlags(subject []byte, flags int) bool {
	return m.finish(m.Exec(subject, flags))
}

// MatchStringWFlags tries to match the specified subject string to the
// pattern. Returns true if the match succeeds.
func (m *Matcher) MatchStringWFlags(subject string, flags int) bool {
	return m.finish(m.ExecString(subject, flags))
}

// span returns the offsets of a capture group and whether they are usable:
// false when the last match failed or the group did not participate.
// Panics with an index-out-of-range error if group exceeds Groups.
//
// Every accessor goes through this gate because PCRE2 leaves the ovector
// unchanged on a failed match, so reading it without the Matches check
// would leak the offsets of the previous match.
func (m *Matcher) span(group int) (start, end int, ok bool) {
	if !m.Matches || m.ovector[2*group] == unset {
		return 0, 0, false
	}

	return int(m.ovector[2*group]), int(m.ovector[2*group+1]), true
}

// Group returns the numbered capture group of the last match. Group 0 is
// the part of the subject which matches the whole pattern; the first
// actual capture group is numbered 1. Capture groups which are not present
// return a nil slice. Panics with an index-out-of-range error if group
// exceeds Groups.
func (m *Matcher) Group(group int) []byte {
	start, end, ok := m.span(group)
	if !ok {
		return nil
	}

	// SubjectB is filled by the string entry points too, so it is always
	// the matched subject. No fallback into GroupString: v1's mutual
	// fallback recursed forever on a nil subject (both fields empty).
	return m.SubjectB[start:end]
}

// GroupString is same as Group, but returns string.
// Panics with an index-out-of-range error if group exceeds Groups.
func (m *Matcher) GroupString(group int) string {
	start, end, ok := m.span(group)
	switch {
	case !ok:
		return ""
	case m.SubjectS == "": // matched through a []byte entry point
		return string(m.SubjectB[start:end])
	}

	return m.SubjectS[start:end]
}

// GroupIndices returns the numbered capture group positions of the last
// match. Group 0 is the whole match. Capture groups which are not present
// return a nil slice. Panics with an index-out-of-range error if group
// exceeds Groups.
func (m *Matcher) GroupIndices(group int) []int {
	start, end, ok := m.span(group)
	if !ok {
		return nil
	}

	return []int{start, end}
}

// Index returns the start and end of the whole match, if the last match
// succeeded. loc[0] is the start and loc[1] is the end.
func (m *Matcher) Index() []int {
	return m.GroupIndices(0)
}

// Present returns true if the numbered capture group is present in the
// last match. Group numbers start at 1. A capture group can be present and
// match the empty string. Panics with an index-out-of-range error if group
// exceeds Groups.
func (m *Matcher) Present(group int) bool {
	_, _, ok := m.span(group)

	return ok
}

// Extract returns the captured strings of the last match: element 0 is the
// whole subject, element i the i-th capture group. Groups which are not
// present are nil slices. Returns nil if the last match failed.
func (m *Matcher) Extract() [][]byte {
	if !m.Matches {
		return nil
	}

	captured := make([][]byte, m.Groups+1)
	captured[0] = m.SubjectB
	for i := 1; i <= m.Groups; i++ {
		captured[i] = m.Group(i)
	}

	return captured
}

// ExtractString is same as Extract, but returns []string.
func (m *Matcher) ExtractString() []string {
	if !m.Matches {
		return nil
	}

	captured := make([]string, m.Groups+1)
	captured[0] = m.SubjectS
	if captured[0] == "" {
		captured[0] = string(m.SubjectB)
	}
	for i := 1; i <= m.Groups; i++ {
		captured[i] = m.GroupString(i)
	}

	return captured
}

// ErrNonUniqueName is wrapped by Named* errors when the pattern was
// compiled with DUPNAMES and the queried name refers to several groups.
// Use Regexp.GroupNumbersForName to enumerate them.
var ErrNonUniqueName = errors.New("name refers to multiple groups (DUPNAMES)")

// name2index resolves a capture group name to its number via
// pcre2_substring_number_from_name.
func (m *Matcher) name2index(name string) (int, error) {
	if m.re.code == nil {
		return 0, fmt.Errorf("pcre: Matcher.Named: uninitialized")
	}

	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	group := int(C.pcre2_substring_number_from_name(
		m.re.code.ptr(), (*C.PCRE2_UCHAR)(unsafe.Pointer(nameC))))
	runtime.KeepAlive(m.re.code)
	switch {
	case group == ERROR_NOUNIQUESUBSTRING:
		return 0, fmt.Errorf("pcre: Matcher.Named: %q: %w", name, ErrNonUniqueName)
	case group < 0:
		return 0, fmt.Errorf("pcre: Matcher.Named: unknown name: %s", name)
	}

	return group, nil
}

// Named returns the value of the named capture group. This is a nil slice
// if the capture group is not present. A non-nil error is returned if the
// name does not refer to a group.
func (m *Matcher) Named(group string) ([]byte, error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return nil, err
	}

	return m.Group(groupNum), nil
}

// NamedString returns the value of the named capture group, or an empty
// string if the capture group is not present. A non-nil error is returned
// if the name does not refer to a group.
func (m *Matcher) NamedString(group string) (string, error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return "", err
	}

	return m.GroupString(groupNum), nil
}

// NamedPresent returns true if the named capture group is present. It
// returns false both when the group did not participate in the match and
// when the name does not refer to a group at all; use Named to tell those
// two cases apart.
func (m *Matcher) NamedPresent(group string) bool {
	groupNum, err := m.name2index(group)
	if err != nil {
		return false
	}

	return m.Present(groupNum)
}
