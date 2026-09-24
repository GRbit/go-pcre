package pcre

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Cyrillic pattern and subject used by the UTF tests, spelled as UTF-8 byte
// escapes so the sources stay ASCII: "Bel[ao]rus" as a character class
// pattern, and "Belarus" with a trailing soft sign as a subject.
const (
	cyrBelarusPattern = "\xd0\x91\xd0\xb5\xd0\xbb[\xd0\xb0\xd0\xbe]\xd1\x80\xd1\x83\xd1\x81"
	cyrBelarus        = "\xd0\x91\xd0\xb5\xd0\xbb\xd0\xb0\xd1\x80\xd1\x83\xd1\x81\xd1\x8c"
)

func checkmatch1(t *testing.T, dostring bool, m *Matcher,
	pattern, subject string, args ...interface{},
) {
	re := MustCompile(pattern, 0)
	var prefix string

	if dostring {
		prefix = "string"

		if m == nil {
			m = re.NewMatcherString(subject, 0)
		} else {
			m.ResetString(re, subject, 0)
		}
	} else {
		prefix = "[]byte"

		if m == nil {
			m = re.NewMatcher([]byte(subject), 0)
		} else {
			m.Reset(re, []byte(subject), 0)
		}
	}

	if len(args) == 0 {
		if m.Matches {
			t.Errorf("prefix='%s' pattern='%s' subject='%s': %s", prefix, pattern, subject, "!Matches")
		}

		return
	}

	if !m.Matches {
		t.Errorf("prefix='%s' pattern='%s' subject='%s': %s", prefix, pattern, subject, "Matches")

		return
	}

	if m.Groups != len(args)-1 {
		t.Error(prefix, pattern, subject, "Groups", m.Groups)

		return
	}

	for i, arg := range args {
		if s, ok := arg.(string); ok {
			if !m.Present(i) {
				t.Error(prefix, pattern, subject,
					"Present", i)
			}

			if g := string(m.Group(i)); g != s {
				t.Error(prefix, pattern, subject,
					"Group", i, g, "!=", s)
			}

			if g := m.GroupString(i); g != s {
				t.Error(prefix, pattern, subject,
					"GroupString", i, g, "!=", s)
			}
		} else if m.Present(i) {
			t.Error(prefix, pattern, subject,
				"!Present", i)
		}
	}
}

func TestMatcher(t *testing.T) {
	var m Matcher
	check := func(pattern, subject string, args ...interface{}) {
		checkmatch1(t, false, nil, pattern, subject, args...)
		checkmatch1(t, true, nil, pattern, subject, args...)
		checkmatch1(t, false, &m, pattern, subject, args...)
		checkmatch1(t, true, &m, pattern, subject, args...)
	}

	check(`^$`, "", "")
	check(`^abc$`, "abc", "abc")
	check(`^(X)*ab(c)$`, "abc", "abc", nil, "c")
	check(`^(X)*ab()c$`, "abc", "abc", nil, "")
	check(`^.*$`, "abc", "abc")
	check(`^.*$`, "a\000c", "a\000c")
	check(`^(.*)$`, "a\000c", "a\000c", "a\000c")
	check(`^abc$`, "abcd")
	check(`^abc$`, "")
}

func TestPartial(t *testing.T) {
	re := MustCompile(`^abc`, 0)
	for _, c := range []struct {
		subject     string
		wantPartial bool
	}{{"ab", true}, {"abc", false}} {
		for _, m := range []*Matcher{
			re.NewMatcherString(c.subject, PARTIAL_SOFT),
			re.NewMatcher([]byte(c.subject), PARTIAL_SOFT),
		} {
			if !m.Matches || m.Partial != c.wantPartial {
				t.Errorf("%q: Matches=%v Partial=%v, want a match with Partial=%v",
					c.subject, m.Matches, m.Partial, c.wantPartial)
			}
		}
	}
}

func TestCaseless(t *testing.T) {
	if !MustCompile("abc", CASELESS).NewMatcherString("Abc", 0).Matches {
		t.Error("CASELESS")
	}
	if MustCompile("abc", 0).NewMatcherString("Abc", 0).Matches {
		t.Error("!CASELESS")
	}
}

func TestNamed(t *testing.T) {
	m := MustCompile("(?<L>a)(?<M>X)*bc(?<DIGITS>\\d*)", 0).NewMatcherString("abc12", 0)
	if !m.Matches {
		t.Fatal("should match")
	}
	if !m.NamedPresent("L") || m.NamedPresent("M") || !m.NamedPresent("DIGITS") {
		t.Error("NamedPresent: want L and DIGITS present, M absent")
	}
	if group, err := m.NamedString("DIGITS"); err != nil || group != "12" {
		t.Errorf("NamedString(DIGITS) = %q, %v", group, err)
	}
	if b, err := m.Named("L"); err != nil || string(b) != "a" {
		t.Errorf("Named(L) = %q, %v", b, err)
	}

	// An unknown name is an error for Named* and plain false for
	// NamedPresent, which cannot tell it from an absent group.
	if _, err := m.Named("NOSUCH"); err == nil {
		t.Error("Named(NOSUCH) should return an error")
	}
	if m.NamedPresent("NOSUCH") {
		t.Error("NamedPresent(NOSUCH) should be false")
	}
	if _, err := new(Matcher).NamedString("L"); err == nil {
		t.Error("NamedString on an uninitialized Matcher should return an error")
	}
}

func TestExtract(t *testing.T) {
	// Extract/ExtractString return the whole subject at [0] and one entry
	// per group: nil/"" for a group that did not participate, whose ovector
	// entries are PCRE2_UNSET and must never be sliced. Both subject forms
	// are checked, which also covers the fallbacks between the string and
	// []byte accessor paths.
	cases := []struct {
		pattern, subject string
		want             []string
		unset            int // group expected to be absent; 0 = none
		index            []int
	}{
		{"b(c)(d)", "abcdef", []string{"abcdef", "c", "d"}, 0, []int{1, 4}},
		{`(X)*ab(c)`, "abc", []string{"abc", "", "c"}, 1, []int{0, 3}},
	}
	for _, c := range cases {
		re := MustCompile(c.pattern, 0)
		for _, str := range []bool{false, true} {
			m := re.NewMatcher([]byte(c.subject), 0)
			if str {
				m = re.NewMatcherString(c.subject, 0)
			}
			name := fmt.Sprintf("%s on %q (string=%v)", c.pattern, c.subject, str)

			if got := m.ExtractString(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s: ExtractString() = %q, want %q", name, got, c.want)
			}
			if got := m.Index(); !reflect.DeepEqual(got, c.index) {
				t.Errorf("%s: Index() = %v, want %v", name, got, c.index)
			}
			raw := m.Extract()
			for i, want := range c.want {
				if string(raw[i]) != want {
					t.Errorf("%s: Extract()[%d] = %q, want %q", name, i, raw[i], want)
				}
				if i == 0 {
					continue
				}
				present := i != c.unset
				if m.Present(i) != present || (raw[i] != nil) != present || (m.GroupIndices(i) != nil) != present {
					t.Errorf("%s: group %d: Present=%v Extract=%v GroupIndices=%v, want present=%v",
						name, i, m.Present(i), raw[i], m.GroupIndices(i), present)
				}
				if string(m.Group(i)) != want || m.GroupString(i) != want {
					t.Errorf("%s: Group(%d) = %q, GroupString = %q, want %q", name, i, m.Group(i), m.GroupString(i), want)
				}
			}
		}
	}
}

func TestMatchFailureClearsGroups(t *testing.T) {
	// PCRE2 leaves the ovector UNCHANGED on a failed match (pcre2api.3),
	// unlike pcre_exec's -1 reset that v1 leaned on. Every accessor must
	// gate on Matches, never on ovector sentinel values: after a success
	// followed by a failure, the stale offsets must not leak out.
	re := MustCompile(`(a)(b)`, 0)
	var m Matcher

	m.Reset(re, []byte("ab"), 0)
	if !m.Matches || string(m.Group(1)) != "a" {
		t.Fatal("first match should succeed with group 1 = a")
	}

	m.Reset(re, []byte("xy"), 0)
	if m.Matches {
		t.Fatal("second match should fail")
	}
	if m.Group(0) != nil || m.GroupString(1) != "" || m.Present(1) ||
		m.Index() != nil || m.GroupIndices(1) != nil || m.Extract() != nil || m.ExtractString() != nil {
		t.Error("accessors leaked the previous match after a failed one")
	}
}

func TestMatchErrorReturnedNotPanicked(t *testing.T) {
	// Intentional v2 divergence (D1): match-time errors land in
	// Matcher.Error as a *MatchError; nothing panics (v1's checkMatch
	// panicked on some codes).
	re := MustCompile("a", UTF)
	m := re.NewMatcher([]byte{0xff, 0xfe, 'a'}, 0) // invalid UTF-8 subject
	var mErr *MatchError
	if m.Matches || !errors.As(m.Error, &mErr) {
		t.Fatalf("invalid UTF-8 subject: Matches=%v Error=%v, want a *MatchError", m.Matches, m.Error)
	}
	if mErr.Code >= 0 || !strings.Contains(mErr.Error(), mErr.Message) {
		t.Errorf("MatchError %+v renders as %q", mErr, mErr.Error())
	}
}

func TestGroupNilSubject(t *testing.T) {
	// A nil subject is legal (an empty pattern matches it) and leaves both
	// subject fields empty. v1's Group and GroupString each deferred to the
	// other in that state and recursed until the stack overflowed. A stack
	// overflow is fatal, so this test crashes the binary rather than
	// failing if that recursion ever returns.
	m := MustCompile("^$", 0).NewMatcher(nil, 0)
	if !m.Matches {
		t.Fatal("^$ should match a nil subject")
	}
	if g := m.Group(0); len(g) != 0 {
		t.Errorf("Group(0) = %q, want empty", g)
	}
	if g := m.GroupString(0); g != "" {
		t.Errorf("GroupString(0) = %q, want empty", g)
	}
	if ex := m.ExtractString(); len(ex) != 1 || ex[0] != "" {
		t.Errorf("ExtractString() = %q, want one empty entry", ex)
	}
}

func TestMatchDataFreedOnGC(t *testing.T) {
	// pcre2_match_data is C memory owned by the Matcher; once matchers
	// become unreachable, GC cleanups must release it.
	before := matchDatasFreed.Load()

	re := MustCompile(`\d+`, 0)
	for i := 0; i < 32; i++ {
		if !re.NewMatcherString("42", 0).Matches {
			t.Fatal("should match")
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for matchDatasFreed.Load() == before {
		if time.Now().After(deadline) {
			t.Fatalf("no match data freed after GC (freed count still %d)", before)
		}
		runtime.GC()
		time.Sleep(time.Millisecond)
	}
}

func TestMatcherFree(t *testing.T) {
	re := MustCompile("a(b)", 0)
	m := re.NewMatcher([]byte("ab"), 0)

	settleCleanups()
	before := matchDatasFreed.Load()
	m.Free()
	m.Free() // idempotent

	if got := matchDatasFreed.Load(); got != before+1 {
		t.Errorf("matchDatasFreed advanced by %d, want 1", got-before)
	}

	// A freed Matcher is reusable through Reset (which re-creates the match
	// data), but direct use panics like an uninitialized one.
	m.Reset(re, []byte("ab"), 0)
	if !m.Matches || string(m.Group(1)) != "b" {
		t.Error("Reset after Free should fully revive the Matcher")
	}

	m.Free()
	defer func() {
		if recover() == nil {
			t.Fatal("Exec on freed Matcher: expected panic")
		}
	}()
	m.Exec([]byte("ab"), 0)
}

func TestConcurrent(t *testing.T) {
	// The documented contract (same as v1, and exactly PCRE2's own:
	// pcre2api.3 MULTITHREADING): a fully constructed Regexp, JIT-compiled
	// or not, may be shared by concurrently matching goroutines, each using
	// its own Matcher; the stateless helpers share pooled Matchers behind
	// the scenes. Run under -race, this test validates that promise.
	for _, jit := range []bool{false, true} {
		re := MustCompile("(Bel[ao]rus)|("+cyrBelarusPattern+")", UTF|CASELESS)
		if jit {
			re = MustCompileJIT("(Bel[ao]rus)|("+cyrBelarusPattern+")", UTF|CASELESS, JIT_COMPLETE)
		}

		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var m Matcher
				for i := 0; i < 200; i++ {
					m.ResetString(re, cyrBelarus+": MTS", 0)
					ok := m.Matches &&
						re.FindString("say "+cyrBelarus, 0) != "" &&
						re.MatchWFlags([]byte(cyrBelarus), 0) &&
						len(re.FindAllIndex([]byte(cyrBelarus+" "+cyrBelarus), 0)) == 2 &&
						re.ReplaceAllString(cyrBelarus, "x", 0) != cyrBelarus
					if !ok {
						t.Errorf("jit=%v: a concurrent match went wrong", jit)

						return
					}
				}
			}()
		}
		wg.Wait()
	}
}

func TestMatcherSwitchingPatternFreesOldMatchData(t *testing.T) {
	// Rebinding a Matcher to another pattern must release the previous
	// match data deterministically (it is sized for the old pattern), while
	// rebinding to the same pattern keeps it.
	re1 := MustCompile("a(b)", 0)
	re2 := MustCompile("c", 0)
	m := re1.NewMatcher([]byte("ab"), 0)

	settleCleanups()
	before := matchDatasFreed.Load()
	m.Reset(re1, []byte("ab"), 0) // same pattern: nothing freed
	if got := matchDatasFreed.Load(); got != before {
		t.Errorf("rebinding to the same pattern freed %d match data, want 0", got-before)
	}
	m.Reset(re2, []byte("c"), 0) // other pattern: the old block goes now
	if got := matchDatasFreed.Load(); got != before+1 {
		t.Errorf("switching patterns freed %d match data, want 1", got-before)
	}
	if !m.Matches || m.Groups != 0 {
		t.Errorf("after switching: Matches=%v Groups=%d, want a match with 0 groups", m.Matches, m.Groups)
	}
}
