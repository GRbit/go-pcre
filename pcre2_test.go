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
	// them at compile time).
	for _, p := range []string{"abc\x00", "a\x00bc", "\x00", "(a\x00b)"} {
		re, err := Compile(p, 0)
		if err != nil {
			t.Errorf("pattern %q: %v", p, err)

			continue
		}
		if g, want := re.Groups(), strings.Count(p, "("); g != want {
			t.Errorf("pattern %q: Groups() = %d, want %d", p, g, want)
		}
	}
}

func TestCodeFreedOnGC(t *testing.T) {
	// Compiled patterns are C memory; they must be released via
	// pcre2_code_free once the Regexp is garbage collected, otherwise every
	// pattern leaks for the life of the process.
	for _, jit := range []bool{false} {
		before := codesFreed.Load()
		for i := 0; i < 32; i++ {
			re := MustCompile(`\d+foo`, 0)
			if re.Groups() != 0 {
				t.Fatal("unexpected group count")
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
	// The reverse guarantee: as long as the Regexp is referenced, GC must
	// NOT free the compiled code.
	re := MustCompile(`(a)(b)`, 0)
	runtime.GC()
	runtime.GC()

	if g := re.Groups(); g != 2 {
		t.Errorf("Groups() after GC = %d, want 2", g)
	}
}

// settleCleanups runs a GC and waits until the free counter stops moving.
// Tests that measure a counter delta around an explicit Free call it
// first: the GC tests before them leave cleanups queued for the objects
// they abandoned, and a cleanup landing inside the measured window would
// be counted as an extra free.
func settleCleanups() {
	runtime.GC()
	for i := 0; i < 100; i++ {
		c := codesFreed.Load()
		time.Sleep(2 * time.Millisecond)
		if codesFreed.Load() == c {
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
	// message rather than dereferencing nothing.
	var re Regexp
	for name, f := range map[string]func(){
		"Groups": func() { re.Groups() },
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
