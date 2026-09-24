package pcre

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCompile(t *testing.T) {
	check := func(p string, groups int) {
		re, err := Compile(p, 0)
		if err != nil {
			t.Error(p, err)
		}
		if g := re.Groups(); g != groups {
			t.Error(p, g)
		}
	}
	check("", 0)
	check("^", 0)
	check("^$", 0)
	check("()", 1)
	check("(())", 2)
	check("((?:))", 1)
}

func TestCompileFail(t *testing.T) {
	// PCRE2 error message texts differ from PCRE1, so unlike the v1 test
	// this asserts the typed error and its offset, not the message string
	// (MIGRATION.md D3).
	check := func(p string, offset int) {
		_, err := Compile(p, 0)
		var cErr *CompileError
		if !errors.As(err, &cErr) {
			t.Errorf("pattern %q: error %v, want *CompileError", p, err)

			return
		}
		if cErr.Pattern != p || cErr.Offset != offset || cErr.Message == "" {
			t.Errorf("pattern %q: CompileError %+v, want offset %d and a message", p, cErr, offset)
		}
	}
	check("(", 1)
	check(`\`, 1)
	check(`abc\`, 4)

	defer func() {
		if _, ok := recover().(*CompileError); !ok {
			t.Error("MustCompile of an invalid pattern should panic with the *CompileError")
		}
	}()
	MustCompile("(", 0)
}

func TestEmbeddedNULPattern(t *testing.T) {
	// Intentional v2 divergence (D2): PCRE2 takes the pattern with an
	// explicit length, so NUL bytes inside patterns are legal (v1 rejected
	// them at compile time) and match literally.
	for _, p := range []string{"abc\x00", "a\x00bc", "\x00", "(a\x00b)"} {
		re, err := Compile(p, 0)
		if err != nil {
			t.Errorf("pattern %q: %v", p, err)

			continue
		}
		if g, want := re.Groups(), strings.Count(p, "("); g != want {
			t.Errorf("pattern %q: Groups() = %d, want %d", p, g, want)
		}
		with, without := "x"+p+"y", strings.ReplaceAll("x"+p+"y", "\x00", "")
		if !re.MatchStringWFlags(with, 0) || re.MatchStringWFlags(without, 0) {
			t.Errorf("pattern %q: must match %q and not %q", p, with, without)
		}
	}
}

func TestCodeFreedOnGC(t *testing.T) {
	// Compiled patterns are C memory; they must be released via
	// pcre2_code_free once the Regexp is garbage collected, otherwise every
	// pattern leaks for the life of the process. JIT data is released by
	// the same call, so the JIT variant is checked too.
	for _, jit := range []bool{false, true} {
		before := codesFreed.Load()
		for i := 0; i < 32; i++ {
			re := MustCompile(`\d+foo`, 0)
			if jit {
				re = MustCompileJIT(`\d+foo`, 0, JIT_COMPLETE)
			}
			if !re.MatchStringWFlags("123foo", 0) {
				t.Fatal("should match")
			}
		}

		deadline := time.Now().Add(2 * time.Second)
		for codesFreed.Load() == before {
			if time.Now().After(deadline) {
				t.Fatalf("jit=%v: no compiled code freed after GC: pattern memory leaks (freed count still %d)", jit, before)
			}
			runtime.GC()
			time.Sleep(time.Millisecond)
		}
	}
}

func TestRegexpUsableAfterGC(t *testing.T) {
	// The reverse guarantee: as long as anything (here: a Matcher) still
	// references the Regexp, GC must NOT free the compiled code or its JIT
	// data.
	for _, jit := range []bool{false, true} {
		re := MustCompile("(Bel[ao]rus)|("+cyrBelarusPattern+")", UTF|CASELESS)
		if jit {
			re = MustCompileJIT("(Bel[ao]rus)|("+cyrBelarusPattern+")", UTF|CASELESS, JIT_COMPLETE)
		}
		m := re.NewMatcherString(cyrBelarus, 0)
		runtime.GC()
		runtime.GC()

		if !m.MatchStringWFlags(cyrBelarus, 0) {
			t.Errorf("jit=%v: match after GC failed: compiled code was freed while still referenced", jit)
		}
	}
}

// settleCleanups runs a GC and waits until the free counters stop moving.
// Tests that measure a counter delta around an explicit Free call it
// first: the GC tests before them leave cleanups queued for the objects
// they abandoned, and a cleanup landing inside the measured window would
// be counted as an extra free.
func settleCleanups() {
	runtime.GC()
	for i := 0; i < 100; i++ {
		c, m := codesFreed.Load(), matchDatasFreed.Load()
		time.Sleep(2 * time.Millisecond)
		if codesFreed.Load() == c && matchDatasFreed.Load() == m {
			return
		}
	}
}

func TestRegexpFree(t *testing.T) {
	// Free releases the pattern exactly once (a second Free is a no-op, not
	// a double free), and any later use panics with a clear message: the
	// accessors have no error returns, and a segfault is the alternative.
	re := MustCompile("abc", 0)
	settleCleanups()
	before := codesFreed.Load()
	re.Free()
	re.Free()
	if got := codesFreed.Load(); got != before+1 {
		t.Errorf("codesFreed advanced by %d, want 1", got-before)
	}

	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "freed") {
			t.Errorf("Groups() on a freed Regexp: panic %v, want a message mentioning freed", r)
		}
	}()
	re.Groups()
}

func TestZeroValueRegexpPanics(t *testing.T) {
	// v1 behavior kept: using a zero-value Regexp panics with a clear
	// message rather than dereferencing nothing. The stateless helpers go
	// through the Matcher pool and must fail the same way, not with a
	// nil-pointer dereference.
	var re Regexp
	for name, f := range map[string]func(){
		"Groups":           func() { re.Groups() },
		"NewMatcher":       func() { re.NewMatcher([]byte("a"), 0) },
		"NewMatcherString": func() { re.NewMatcherString("a", 0) },
		"MatchWFlags":      func() { re.MatchWFlags([]byte("a"), 0) },
		"FindAllIndex":     func() { re.FindAllIndex([]byte("a"), 0) },
		"ReplaceAll":       func() { re.ReplaceAll([]byte("a"), nil, 0) },
	} {
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "uninitialized") {
					t.Errorf("%s on a zero Regexp: panic %v, want a message mentioning uninitialized", name, r)
				}
			}()
			f()
		}()
	}
}

func TestFreedRegexpPanicsEverywhere(t *testing.T) {
	// Every entry point that touches the compiled pattern, or a fact cached
	// from it, must fail the same way after Free: a panic naming the freed
	// object, never a stale answer and never a nil dereference.
	re := MustCompile(`(?<n>a)`, 0)
	if !re.MatchStringWFlags("a", 0) {
		t.Fatal("sanity: should match before Free")
	}
	re.Free()

	var m Matcher
	for name, f := range map[string]func(){
		"Groups":              func() { re.Groups() },
		"CaptureNames":        func() { re.CaptureNames() },
		"GroupNumbersForName": func() { re.GroupNumbersForName("n") },
		"Info":                func() { _, _ = re.Info(INFO_MINLENGTH) },
		"JITCompiled":         func() { re.JITCompiled() },
		"Study":               func() { _ = re.Study(JIT_COMPLETE) },
		"NewMatcher":          func() { re.NewMatcher([]byte("a"), 0) },
		"Reset":               func() { m.Reset(re, []byte("a"), 0) },
		"MatchWFlags":         func() { re.MatchWFlags([]byte("a"), 0) },
		"FindIndex":           func() { re.FindIndex([]byte("a"), 0) },
		"FindAllIndex":        func() { re.FindAllIndex([]byte("a"), 0) },
		"ReplaceAll":          func() { re.ReplaceAll([]byte("a"), nil, 0) },
		"ReplaceAllTemplate":  func() { _, _ = re.ReplaceAllTemplate([]byte("a"), nil, 0) },
	} {
		func() {
			defer func() {
				if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "freed") {
					t.Errorf("%s on a freed Regexp: panic %v, want a message mentioning freed", name, r)
				}
			}()
			f()
		}()
	}
}
