// Package pcre provides access to the Perl Compatible Regular Expression
// library, PCRE.
//
// It implements two main types, Regexp and Matcher. Regexp objects
// store a compiled regular expression. They consist of two immutable
// parts: pcre and pcre_extra. You can add pcre_extra to Compiled Regexp by
// studying it with Study() function.
// Compilation of regular expressions using Compile or MustCompile is
// slightly expensive, so these objects should be kept and reused,
// instead of compiling them from scratch for each matching attempt.
// CompileJIT and MustCompileJIT are way more expensive than ordinary
// methods, because they run Study() func after Regexp compiled but gives
// much better performance:
// https://zherczeg.github.io/sljit/regex_perf.html
//
// Matcher objects keep the results of a match against a []byte or
// string subject. The Group and GroupString functions provide access
// to capture groups; both versions work no matter if the subject was a
// []byte or string.
//
// Matcher objects contain some temporary space and refer to the original
// subject. They are mutable and can be reused (using Match,
// MatchString, Reset or ResetString).
//
// Most Matcher.*String methods are just links to []byte methods, so keep
// this in mind.
//
// Concurrency: a Regexp, once fully constructed, is safe for concurrent
// matching from multiple goroutines. "Fully constructed" means Compile has
// returned and, if you use it, Study has completed: Study mutates the Regexp
// in place, so calling it concurrently with matching (or with another Study
// of the same Regexp) is a data race. A Matcher is stateful and must only be
// used by one goroutine at a time; give each goroutine its own Matcher —
// creating one is cheap compared to compiling.
//
// For details on the regular expression language implemented by this
// package and the flags defined below see the PCRE documentation.
// http://www.pcre.org/pcre.txt

// Copyright (c) 2011 Florian Weimer. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package pcre

/*
#cgo pkg-config: libpcre
#include <pcre.h>
#include <string.h>
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync/atomic"
	"unsafe"
)

// Layout of the pcre_extra struct, shared with tests (test files cannot use cgo).
const sizeofPcreExtra = C.sizeof_struct_pcre_extra

var studyDataOffset = unsafe.Offsetof(C.struct_pcre_extra{}.study_data)

// studiesFreed counts pcre_free_study calls; it exists for tests to observe
// that finalizers actually release study data.
var studiesFreed uint64

// pcreConfig exposes raw pcre_config to tests (test files cannot use cgo).
func pcreConfig(f int, where unsafe.Pointer) {
	C.pcre_config(C.int(f), where)
}

// Config function returns information about libpcre configuration.
// Function pass flag f to C.pcre_config() func, and convert returned
// value to string type.
// http://www.pcre.org/original/doc/html/pcre_config.html
func Config(f int) string {
	if f == C.PCRE_CONFIG_JITTARGET {
		var jitTarget *C.char
		C.pcre_config(C.PCRE_CONFIG_JITTARGET, unsafe.Pointer(&jitTarget))

		return C.GoString(jitTarget)
	}

	// pcre_config writes an unsigned long for these two queries (8 bytes on
	// LP64), unlike the plain int of every other numeric query; a C.int
	// buffer would be overflowed.
	if f == C.PCRE_CONFIG_MATCH_LIMIT || f == C.PCRE_CONFIG_MATCH_LIMIT_RECURSION {
		var l C.ulong
		C.pcre_config(C.int(f), unsafe.Pointer(&l))

		return strconv.FormatUint(uint64(l), 10)
	}

	var i C.int
	C.pcre_config(C.int(f), unsafe.Pointer(&i))

	return strconv.Itoa(int(i))
}

// ConfigAll function returns string, which contains  all information
// you can access by pcre_config() function
func ConfigAll() string {
	var i C.int

	C.pcre_config(C.PCRE_CONFIG_JIT, unsafe.Pointer(&i))
	ret := fmt.Sprintf("jit: %d\n", int32(i))

	var jitTarget *C.char
	C.pcre_config(C.PCRE_CONFIG_JITTARGET, unsafe.Pointer(&jitTarget))

	ret += fmt.Sprintf("jittarget: %s\n", C.GoString(jitTarget))
	C.pcre_config(C.PCRE_CONFIG_LINK_SIZE, unsafe.Pointer(&i))
	ret += fmt.Sprintf("link_size: %d\n", int32(i))

	// These two queries are written as unsigned long, not int; see Config.
	var l C.ulong
	C.pcre_config(C.PCRE_CONFIG_MATCH_LIMIT, unsafe.Pointer(&l))
	ret += fmt.Sprintf("match_limit: %d\n", uint64(l))
	C.pcre_config(C.PCRE_CONFIG_MATCH_LIMIT_RECURSION, unsafe.Pointer(&l))
	ret += fmt.Sprintf("match_limit_recursion: %d\n", uint64(l))
	C.pcre_config(C.PCRE_CONFIG_NEWLINE, unsafe.Pointer(&i))
	ret += fmt.Sprintf("newline: %d\n", int32(i))
	C.pcre_config(C.PCRE_CONFIG_BSR, unsafe.Pointer(&i))
	ret += fmt.Sprintf("bsr: %d\n", int32(i))
	C.pcre_config(C.PCRE_CONFIG_POSIX_MALLOC_THRESHOLD, unsafe.Pointer(&i))
	ret += fmt.Sprintf("posix_malloc_threshold: %d\n", int32(i))
	C.pcre_config(C.PCRE_CONFIG_STACKRECURSE, unsafe.Pointer(&i))
	ret += fmt.Sprintf("stackrecurse: %d\n", int32(i))
	C.pcre_config(C.PCRE_CONFIG_UTF16, unsafe.Pointer(&i))
	ret += fmt.Sprintf("utf16: %d\n", int32(i))
	C.pcre_config(C.PCRE_CONFIG_UTF32, unsafe.Pointer(&i))
	ret += fmt.Sprintf("utf32: %d\n", int32(i))
	C.pcre_config(C.PCRE_CONFIG_UTF8, unsafe.Pointer(&i))
	ret += fmt.Sprintf("utf8: %d\n", int32(i))
	C.pcre_config(C.PCRE_CONFIG_UNICODE_PROPERTIES, unsafe.Pointer(&i))
	ret += fmt.Sprintf("unicode_properties: %d\n", int32(i))

	return ret
}

// Number of bytes in the compiled pattern
func pcreSize(ptr *C.pcre) (size C.size_t) {
	C.pcre_fullinfo(ptr, nil, C.PCRE_INFO_SIZE, unsafe.Pointer(&size))

	return
}

// Number of capture groups
func pcreGroups(ptr *C.pcre) (count C.int) {
	C.pcre_fullinfo(ptr, nil, C.PCRE_INFO_CAPTURECOUNT, unsafe.Pointer(&count))

	return
}

type CaptureName struct {
	Name  string
	Index int
}

// Get names of capturing parentheses
func pcreCaptureNames(ptr *C.pcre) []CaptureName {
	var nameCount C.int
	C.pcre_fullinfo(ptr, nil, C.PCRE_INFO_NAMECOUNT, unsafe.Pointer(&nameCount))
	result := make([]CaptureName, nameCount)
	if nameCount > 0 {
		var nameEntrySize C.int
		C.pcre_fullinfo(ptr, nil, C.PCRE_INFO_NAMEENTRYSIZE, unsafe.Pointer(&nameEntrySize))
		var data unsafe.Pointer
		C.pcre_fullinfo(ptr, nil, C.PCRE_INFO_NAMETABLE, unsafe.Pointer(&data))
		for nameIndex := 0; nameIndex < int(nameCount); nameIndex++ {
			offset := nameIndex * int(nameEntrySize)

			// Bytes 0 and 1 contains name index (most significant byte first)
			// From byte 2 starting name (zero-ended)
			high_index := *((*byte)(unsafe.Add(data, offset+0)))
			low_index := *((*byte)(unsafe.Add(data, offset+1)))
			index := int(high_index)*256 + int(low_index)

			// Building capture name from byte 2
			buff := bytes.NewBufferString("")
			for charOffset := 2; charOffset < int(nameEntrySize); charOffset++ {
				c := *((*byte)(unsafe.Add(data, offset+charOffset)))
				if c == 0 {
					break
				}
				buff.WriteByte(c)
			}
			result[nameIndex] = CaptureName{
				Name:  buff.String(),
				Index: index,
			}
		}
	}

	return result
}

// parseFlagsRe matches a leading "(?letters)" candidate flag group.
var parseFlagsRe = MustCompile(`^\(\?[a-zA-Z]+?\)`, 0)

// flagLetters maps "(?flags)" letters to the compile flags they stand for.
var flagLetters = map[byte]int{
	'i': CASELESS,
	'D': DOLLAR_ENDONLY,
	's': DOTALL,
	'J': DUPNAMES,
	'x': EXTENDED,
	'X': EXTRA,
	'm': MULTILINE,
	'U': UNGREEDY,
	'u': UTF8 | UCP,
}

// ParseFlags returns string with regex pattern and int with pcre flags.
// Flags are specified before the regex in form like this "(?flags)regex"
// Supported symbols i=CASELESS; m=MULTILINE; s=DOTALL; U=UNGREEDY; J=DUPNAMES;
// x=EXTENDED; X=EXTRA; D=DOLLAR_ENDONLY; u=UTF8|UCP;
//
// Caveat (kept for backward compatibility): every leading "(?letters)" group
// is consumed, and letters that are not flags are silently ignored. This
// means PCRE constructs made of letters only, such as "(?R)", are stripped
// from the beginning of the pattern rather than passed to pcre_compile. Do
// not use ParseFlags/CompileParse with such patterns.
func ParseFlags(ptr string) (string, int) {
	flags := 0

	for {
		fStr := parseFlagsRe.FindString(ptr, 0)
		if fStr == "" {
			return ptr, flags
		}

		for i := 2; i < len(fStr)-1; i++ { // letters between "(?" and ")"
			flags |= flagLetters[fStr[i]] // unknown letters add nothing
		}

		ptr = ptr[len(fStr):]
	}
}

// extraHandle owns the pcre_extra block returned by pcre_study. The block
// (and the JIT code it may reference) is C memory that only pcre_free_study
// can release, so it is kept alive here and freed by a finalizer once the
// last Regexp copy referring to it becomes unreachable.
type extraHandle struct {
	p *C.pcre_extra
}

func freeExtra(h *extraHandle) {
	C.pcre_free_study(h.p)
	h.p = nil
	atomic.AddUint64(&studiesFreed, 1)
}

// Regexp is a reference to a compiled regular expression.
// Use Compile or MustCompile to create such objects.
// Once fully constructed (compiled and, if desired, studied) it is safe
// for concurrent use by multiple goroutines; see the package comment.
type Regexp struct {
	expr string // as passed to Compile

	ptr   []byte
	extra *extraHandle
}

// Compile try to compile the pattern. If an error occurs, the second return
// value is non-nil.
func Compile(pattern string, flags int) (Regexp, error) {
	patternC := C.CString(pattern)
	defer C.free(unsafe.Pointer(patternC))

	if clen := int(C.strlen(patternC)); clen != len(pattern) {
		return Regexp{}, fmt.Errorf("%s (%d): %s",
			pattern, clen, "NUL byte in pattern",
		)
	}

	var errPtr *C.char
	var errOffset C.int
	ptr := C.pcre_compile(patternC, C.int(flags), &errPtr, &errOffset, nil)
	if ptr == nil {
		return Regexp{}, fmt.Errorf("%s (%d): %s",
			pattern, int(errOffset), C.GoString(errPtr),
		)
	}

	defer C.free(unsafe.Pointer(ptr))
	size := pcreSize(ptr)

	re := Regexp{
		expr:  pattern,
		ptr:   C.GoBytes(unsafe.Pointer(ptr), C.int(size)),
		extra: nil,
	}

	return re, nil
}

// CompileParse try to parse flags of regex and compile it. If an error occurs,
// the second return value is non-nil. Flags are specified before the regex in form like this "(?flags)regex"
func CompileParse(ptr string) (Regexp, error) {
	ptr, f := ParseFlags(ptr)
	retRegex, err := Compile(ptr, f)
	if err != nil {
		return Regexp{}, fmt.Errorf("can't compile/study pcre regexp: pattern='%s' flags='%b'", ptr, f)
	}

	return retRegex, nil
}

// CompileJIT compiles pattern with jit compilation. flagC is Compile flags,
// flagS is study flag.
func CompileJIT(pattern string, flagsC, flagsS int) (Regexp, error) {
	re, err := Compile(pattern, flagsC)
	if err != nil {
		return re, err
	}

	if (flagsS & STUDY_JIT_COMPILE) == 0 {
		return re, errors.New("flagsS must contains pcre.STUDY_JIT_COMPILE flag")
	}

	if errS := re.Study(flagsS); errS != nil {
		return re, fmt.Errorf("study error: %w", errS)
	}

	return re, nil
}

// CompileParseJIT try to parse flags of regex and compile it with JIT optimization.
// If an error occurs, the second return value is non-nil.
func CompileParseJIT(ptr string, flags int) (Regexp, error) {
	ptr, f := ParseFlags(ptr)
	retRegex, err := CompileJIT(ptr, f, flags)
	if err != nil {
		return Regexp{},
			fmt.Errorf("can't compile/study pcre regexp: pattern='%s' flags=%b flagsJIT=%b",
				ptr, f, flags)
	}

	return retRegex, nil
}

// MustCompile is same as Compile but if compilation fails, panic.
func MustCompile(pattern string, flag int) (re Regexp) {
	re, err := Compile(pattern, flag)
	if err != nil {
		panic(err)
	}

	return
}

// MustCompileParse is same as CompileParse but if compilation fails, panic.
func MustCompileParse(pattern string) (re Regexp) {
	re, err := CompileParse(pattern)
	if err != nil {
		panic(err)
	}

	return
}

// MustCompileJIT is same as CompileJIT but if compilation fails, panic.
func MustCompileJIT(pattern string, flagsC, flagsS int) (re Regexp) {
	re, err := CompileJIT(pattern, flagsC, flagsS)
	if err != nil {
		panic(err)
	}

	return
}

// MustCompileParseJIT is same as CompileParseJIT but if compilation fails, panic.
func MustCompileParseJIT(pattern string, flags int) (re Regexp) {
	re, err := CompileParseJIT(pattern, flags)
	if err != nil {
		panic(err)
	}

	return
}

// FindAllIndex returns successive matches of the expression.
func (re *Regexp) FindAllIndex(bytes []byte, flags int) (r [][]int) {
	m := re.NewMatcher(bytes, flags)
	offset := 0

	for offset <= len(bytes) && m.MatchWFlags(bytes[offset:], flags) {
		start := offset + int(m.oVector[0])
		end := offset + int(m.oVector[1])
		r = append(r, []int{start, end})
		if end > offset {
			offset = end
		} else {
			offset++
		}
	}

	return
}

// FindIndex returns the start and end of the first match, or nil if no match.
// loc[0] is the start and loc[1] is the end.
func (re *Regexp) FindIndex(bytes []byte, flags int) []int {
	m := re.NewMatcher(bytes, flags)
	if m.Matches {
		return []int{int(m.oVector[0]), int(m.oVector[1])}
	}

	return nil
}

// FindString returns the text of the first match, or "" if there is no
// match. Note that "" is also returned for a valid empty-width match, so a
// zero result does not necessarily mean the pattern did not match; use
// FindIndex to distinguish the two.
func (re *Regexp) FindString(s string, flags int) string {
	m := re.NewMatcher([]byte(s), flags)
	if m.Matches {
		return s[int(m.oVector[0]):int(m.oVector[1])]
	}

	return ""
}

// Groups return the number of capture groups in the compiled regexp pattern.
func (re Regexp) Groups() int {
	if re.ptr == nil {
		panic("Regexp.Groups: uninitialized")
	}

	return int(pcreGroups((*C.pcre)(unsafe.Pointer(&re.ptr[0]))))
}

// CaptureNames returns the names of capturing groups in the compiled regexp
// pattern. Each item contains name and index of capturing parentheses.
func (re Regexp) CaptureNames() []CaptureName {
	if re.ptr == nil {
		panic("Regexp.CaptureNames: uninitialized")
	}

	data := pcreCaptureNames((*C.pcre)(unsafe.Pointer(&re.ptr[0])))
	return data
}

// MatchWFlags tries to match the specified byte array slice to the pattern.
// Returns true if the match succeeds.
func (re *Regexp) MatchWFlags(subject []byte, flags int) bool {
	m := re.NewMatcher(subject, flags)

	return m.Matches
}

// MatchStringWFlags is the same as MatchWFlags, but accept string as argument.
func (re *Regexp) MatchStringWFlags(subject string, flags int) bool {
	m := re.NewMatcher([]byte(subject), flags)

	return m.Matches
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

// ReplaceAll return a copy of a byte slice with pattern matches replaced by repl.
func (re Regexp) ReplaceAll(bytes, repl []byte, flags int) []byte {
	var m Matcher
	m.init(re)
	r := make([]byte, 0, len(bytes))

	// Canonical PCRE global-match loop (see pcredemo.c), which is also what
	// Perl's s///g does: after an empty match, retry at the same position
	// requiring a non-empty match; if none, copy one byte and keep scanning.
	retryFlags := 0
	for {
		if !m.MatchWFlags(bytes, flags|retryFlags) {
			if retryFlags == 0 || len(bytes) == 0 {
				break
			}
			r = append(r, bytes[0])
			bytes = bytes[1:]
			retryFlags = 0
			continue
		}

		if m.oVector[1] < m.oVector[0] {
			// \K in an assertion set the match start after its end, e.g.
			// `(?=ab\K)`: the match consumed nothing, so continuing would
			// loop forever. The reference loop (pcre2demo.c) abandons the
			// run here; keep the rest of the subject unchanged.
			break
		}

		r = append(append(r, bytes[:m.oVector[0]]...), repl...)
		empty := m.oVector[0] == m.oVector[1]
		bytes = bytes[m.oVector[1]:]
		if !empty {
			retryFlags = 0
			continue
		}
		if len(bytes) == 0 {
			return r // empty match at the end of the subject
		}
		retryFlags = NOTEMPTY_ATSTART | ANCHORED
	}

	return append(r, bytes...)
}

// ReplaceAllString is same as ReplaceAll, but accept strings as arguments.
// It delegates to ReplaceAll: converting the subject once is far cheaper
// than the string-slicing loop it used to run, which re-converted the
// remaining subject to []byte inside every ExecString call.
func (re Regexp) ReplaceAllString(subj, repl string, flags int) string {
	return string(re.ReplaceAll([]byte(subj), []byte(repl), flags))
}

// Study regexp and add pcre_extra information to it, which gives huge
// speed boost when matching. If an error occurs, return value is non-nil.
// Studying can be quite a heavy optimization, but it's worth it.
//
// Study mutates the Regexp in place: it must complete before the Regexp is
// shared with other goroutines. Calling it concurrently with matching, or
// with another Study of the same Regexp, is a data race.
func (re *Regexp) Study(flags int) error {
	if re.extra != nil {
		return errors.New("regexp already optimized")
	}

	var err *C.char
	extra := C.pcre_study((*C.pcre)(unsafe.Pointer(&re.ptr[0])), C.int(flags), &err)
	if err != nil {
		return errors.New(C.GoString(err))
	}

	if extra == nil {
		return nil // no optimization data available, not an error
	}

	// The block must stay alive as long as this Regexp is used: it holds the
	// study data pcre_exec reads and may reference JIT-compiled code. Both
	// can only be released together via pcre_free_study, which the finalizer
	// calls once no Regexp copy references the handle anymore.
	h := &extraHandle{p: extra}
	runtime.SetFinalizer(h, freeExtra)
	re.extra = h

	return nil
}

// Matcher objects provide a place for storing match results.
// They can be created by the NewMatcher and NewMatcherString functions,
// or they can be initialized with Reset or ResetString.
// A Matcher is not safe for concurrent use: it holds the state of the last
// match. Use one Matcher per goroutine.
type Matcher struct {
	re       Regexp
	Groups   int
	oVector  []int32 // space for capture offsets, int32 is analog for C.int type
	Matches  bool    // last match was successful
	Partial  bool    // was the last match a partial match?
	Error    error   // pcre_exec error from last match
	SubjectS string  // contain found subject as string
	SubjectB []byte  // contain found subject as []byte
}

// Exec tries to match the specified byte array slice to the current
// pattern. Returns exec result.
// C docs http://www.pcre.org/original/doc/html/pcre_exec.html
func (m *Matcher) Exec(subject []byte, flags int) int {
	if m.re.ptr == nil {
		panic("Matcher.Exec: uninitialized")
	}

	length := len(subject)
	m.SubjectS = ""
	m.SubjectB = subject
	if length == 0 {
		subject = []byte{0} // make first character addressable
	}

	subjectP := (*C.char)(unsafe.Pointer(&subject[0]))

	return m.exec(subjectP, length, flags)
}

// ExecString is same as Exec, but accept string as argument
func (m *Matcher) ExecString(subject string, flags int) int {
	if m.re.ptr == nil {
		panic("Matcher.Match: uninitialized")
	}

	b := []byte(subject)
	length := len(b)
	m.SubjectS = subject
	m.SubjectB = b
	if length == 0 {
		b = []byte{0} // make first character addressable
	}

	subjectP := (*C.char)(unsafe.Pointer(&b[0]))

	return m.exec(subjectP, length, flags)
}

func (m *Matcher) exec(subjectP *C.char, length, flags int) int {
	var extra *C.pcre_extra
	if m.re.extra != nil {
		extra = m.re.extra.p
	}

	rc := C.pcre_exec((*C.pcre)(unsafe.Pointer(&m.re.ptr[0])), extra,
		subjectP, C.int(length), 0, C.int(flags),
		(*C.int)(unsafe.Pointer(&m.oVector[0])), C.int(len(m.oVector)))

	// Keep the handle (and thus the C extra block) alive for the duration of
	// the pcre_exec call above; without this the finalizer could free it
	// mid-call if the Matcher itself is no longer referenced afterwards.
	runtime.KeepAlive(m.re.extra)

	return int(rc)
}

// Extract returns the captured string with sub-matches of the last match
// (performed by Matcher, MatcherString, Reset, ResetString, Match,
// or MatchString). Group 0 is the part of the subject which matches
// the whole pattern; the first actual capture group is numbered 1.
// Capture groups which are not present return a nil slice.
func (m *Matcher) Extract() [][]byte {
	if !m.Matches {
		return nil
	}

	capturedTexts := make([][]byte, m.Groups+1)
	capturedTexts[0] = m.SubjectB

	for i := 1; i < m.Groups+1; i++ {
		start := m.oVector[2*i]
		end := m.oVector[2*i+1]
		if start >= 0 {
			capturedTexts[i] = m.SubjectB[start:end]
		} // else: group did not participate in the match, leave nil
	}

	return capturedTexts
}

// ExtractString is same as Extract, but returns []string
func (m *Matcher) ExtractString() []string {
	if !m.Matches {
		return nil
	}

	if m.SubjectS == "" {
		raw := m.Extract()
		res := make([]string, len(raw))
		for i, b := range raw {
			res[i] = string(b)
		}
		return res
	}

	capturedTexts := make([]string, m.Groups+1)
	capturedTexts[0] = m.SubjectS

	for i := 1; i < m.Groups+1; i++ {
		start := m.oVector[2*i]
		end := m.oVector[2*i+1]
		if start >= 0 {
			capturedTexts[i] = m.SubjectS[start:end]
		} // else: group did not participate in the match, leave empty
	}

	return capturedTexts
}

func (m *Matcher) init(re Regexp) {
	m.Matches = false
	if len(m.re.ptr) != 0 && len(re.ptr) != 0 && &m.re.ptr[0] == &re.ptr[0] &&
		m.re.extra == re.extra {
		// Skip group count extraction if the matcher has
		// already been initialized with the same regular
		// expression. The extra handle is compared too: the same pattern
		// gains one when it is Studied, and the matcher must pick it up.
		return
	}

	m.re = re
	if re.ptr != nil {
		m.Groups = re.Groups()
	}

	if oVectorLen := 3 * (1 + m.Groups); len(m.oVector) < oVectorLen {
		m.oVector = make([]int32, int32(oVectorLen))
	}
}

// Group returns the numbered capture group of the last match (performed by
// Matcher, MatcherString, Reset, ResetString, Match, or MatchString).
// Group 0 is the part of the subject which matches the whole pattern;
// the first actual capture group is numbered 1. Capture groups which
// are not present return a nil slice.
// Panics with an index-out-of-range error if group exceeds Groups.
func (m *Matcher) Group(group int) []byte {
	if m.SubjectB == nil {
		if !m.Matches {
			return nil
		}
		return []byte(m.GroupString(group))
	}

	start := m.oVector[2*group]
	end := m.oVector[2*group+1]
	if start >= 0 {
		return m.SubjectB[start:end]
	}

	return nil
}

// GroupIndices returns the numbered capture group positions of the last match
// (performed by Matcher, MatcherString, Reset, ResetString, Match,
// or MatchString). Group 0 is the part of the subject which matches
// the whole pattern; the first actual capture group is numbered 1.
// Capture groups which are not present return a nil slice.
// Panics with an index-out-of-range error if group exceeds Groups.
func (m *Matcher) GroupIndices(group int) []int {
	start := m.oVector[2*group]
	end := m.oVector[2*group+1]
	if start >= 0 {
		return []int{int(start), int(end)}
	}

	return nil
}

// GroupString is same as Group, but returns string.
// Panics with an index-out-of-range error if group exceeds Groups.
func (m *Matcher) GroupString(group int) string {
	if m.SubjectS == "" {
		if !m.Matches {
			return ""
		}
		return string(m.Group(group))
	}

	start := m.oVector[2*group]
	end := m.oVector[2*group+1]
	if start >= 0 {
		return m.SubjectS[start:end]
	}

	return ""
}

// Index returns the start and end of the first match, if a previous
// call to Matcher, MatcherString, Reset, ResetString, Match or
// MatchString succeeded. loc[0] is the start and loc[1] is the end.
func (m *Matcher) Index() []int {
	if !m.Matches {
		return nil
	}

	return []int{int(m.oVector[0]), int(m.oVector[1])}
}

// MatchWFlags tries to match the specified byte array slice to the
// pattern. Returns true if the match succeeds.
func (m *Matcher) MatchWFlags(subject []byte, flags int) bool {
	rc := m.Exec(subject, flags)

	m.Matches, m.Error = checkMatch(rc)
	m.Partial = rc == C.PCRE_ERROR_PARTIAL

	return m.Matches
}

// MatchStringWFlags tries to match the specified subject string to the pattern.
// Returns true if the match succeeds.
func (m *Matcher) MatchStringWFlags(subject string, flags int) bool {
	rc := m.ExecString(subject, flags)

	m.Matches, m.Error = checkMatch(rc)
	m.Partial = rc == ERROR_PARTIAL

	return m.Matches
}

func checkMatch(rc int) (bool, error) {
	switch {
	case rc >= 0 || rc == ERROR_PARTIAL:
		return true, nil
	case rc == ERROR_NOMATCH:
		return false, nil
	case rc == ERROR_NULL:
		return false, fmt.Errorf("%d, pcre_exec: one or more variables passed to pcre_exec == NULL", rc)
	case rc == ERROR_BADOPTION:
		return false, fmt.Errorf("%d, pcre_exec: An unrecognized bit was set in the options argument", rc)
	case rc == ERROR_BADMAGIC:
		return false, fmt.Errorf("%d, pcre_exec: invalid option flag", rc)
	case rc == ERROR_UNKNOWN_OPCODE:
		return false, fmt.Errorf("%d, pcre_exec: an unknown item was encountered in the compiled pattern", rc)
	case rc == ERROR_NOMEMORY:
		return false, fmt.Errorf("%d, pcre_exec: match limit", rc)
	case rc == ERROR_MATCHLIMIT:
		return false, fmt.Errorf("%d, pcre_exec: backtracking (match) limit was reached", rc)
	case rc == ERROR_BADUTF8:
		return false, fmt.Errorf("%d, pcre_exec: string that contains an invalid UTF-8 byte sequence was passed as a subject", rc)
	case rc == ERROR_RECURSIONLIMIT:
		return false, fmt.Errorf("%d, pcre_exec: recursion limit", rc)
	case rc == ERROR_JIT_STACKLIMIT:
		return false, fmt.Errorf("%d, pcre_exec: error JIT stack limit", rc)
	case rc == ERROR_INTERNAL:
		panic("pcre_exec: INTERNAL ERROR")
	case rc == ERROR_BADCOUNT:
		panic("pcre_exec: INTERNAL ERROR")
	}

	panic("unexpected return code from pcre_exec: " + strconv.Itoa(rc))
}

func (m *Matcher) name2index(name string) (group int, err error) {
	if m.re.ptr == nil {
		err = fmt.Errorf("Matcher.Named: uninitialized")

		return
	}

	name1 := C.CString(name)
	defer C.free(unsafe.Pointer(name1))

	group = int(C.pcre_get_stringnumber(
		(*C.pcre)(unsafe.Pointer(&m.re.ptr[0])), name1))

	if group < 0 {
		err = fmt.Errorf("Matcher.Named: unknown name: %s", name)

		return
	}

	return
}

// Named returns the value of the named capture group. This is a nil slice
// if the capture group is not present. A non-nil error is returned if the
// name does not refer to a group.
func (m *Matcher) Named(group string) (g []byte, err error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return
	}

	return m.Group(groupNum), nil
}

// NamedPresent returns true if the named capture group is present. It
// returns false both when the group did not participate in the match and
// when the name does not refer to a group at all; use Named to tell those
// two cases apart.
func (m *Matcher) NamedPresent(group string) (pres bool) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return false
	}

	return m.Present(groupNum)
}

// NamedString returns the value of the named capture group, or an empty
// string if the capture group is not present. A non-nil error is returned
// if the name does not refer to a group.
func (m *Matcher) NamedString(group string) (g string, err error) {
	groupNum, err := m.name2index(group)
	if err != nil {
		return
	}

	return m.GroupString(groupNum), nil
}

// Present returns true if the numbered capture group is present in the last
// match (performed by Matcher, MatcherString, Reset, ResetString,
// Match, or MatchString). Group numbers start at 1. A capture group
// can be present and match the empty string.
// Panics with an index-out-of-range error if group exceeds Groups.
func (m *Matcher) Present(group int) bool {
	return m.oVector[2*group] >= 0
}

// Reset switches the matcher object to the specified pattern and subject.
func (m *Matcher) Reset(re Regexp, subject []byte, flags int) {
	if re.ptr == nil {
		panic("Regexp.Matcher: uninitialized")
	}

	m.init(re)
	m.MatchWFlags(subject, flags)
}

// ResetString switches the matcher object to the specified pattern and subject
// string.
func (m *Matcher) ResetString(re Regexp, subject string, flags int) {
	if re.ptr == nil {
		panic("Regexp.Matcher: uninitialized")
	}

	m.init(re)
	m.MatchStringWFlags(subject, flags)
}

// Copyright (c) 2011 Florian Weimer. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
