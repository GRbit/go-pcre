// Copyright (C) 2011 Florian Weimer <fw@deneb.enyo.de>

package pcre

import (
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func TestConfigMatchLimitBufferWidth(t *testing.T) {
	// For these two queries pcre_config writes an unsigned long — 8 bytes
	// on LP64 (pcre_config.c: *((unsigned long int *)where) = MATCH_LIMIT)
	// — unlike the plain int it writes for the other numeric queries.
	// Prove the write width with a poisoned 64-bit buffer, then require
	// Config to return the full correctly-read value. Passing a 4-byte
	// buffer, as Config once did, overflows it.
	for _, f := range []int{CONFIG_MATCH_LIMIT, CONFIG_MATCH_LIMIT_RECURSION} {
		v := uint64(0xFFFFFFFF00000000)
		pcreConfig(f, unsafe.Pointer(&v))

		if v>>32 == 0xFFFFFFFF {
			// The high half survived: this platform writes 4 bytes and an
			// int-sized buffer is fine here. Nothing further to check.
			t.Logf("flag %d: 4-byte write on this platform", f)
			continue
		}

		// High half overwritten: 8-byte write confirmed, so Config must
		// read through a 64-bit buffer to be correct (and to not smash
		// whatever lives next to a smaller one).
		want := strconv.FormatUint(v, 10)
		if got := Config(f); got != want {
			t.Errorf("Config(%d) = %q, want %q", f, got, want)
		}
		if all := ConfigAll(); !strings.Contains(all, want) {
			t.Errorf("ConfigAll() does not contain the correct value %q", want)
		}
	}
}

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
	check := func(p, msg string) {
		_, err := Compile(p, 0)

		switch {
		case err == nil:
			t.Error(p)
		case err.Error() != msg:
			t.Error(p, "Message:", err.Error())
		}
	}

	check("(", "( (1): missing )")
	check(`\`, `\ (1): \ at end of pattern`)
	check(`abc\`, `abc\ (4): \ at end of pattern`)
	check("abc\000", "abc\000 (3): NUL byte in pattern")
	check("a\000bc", "a\000bc (1): NUL byte in pattern")
}

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
		t.Logf("%v", m.Matches)
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
}

func TestNewMatcherJIT(t *testing.T) {
	re := MustCompileJIT(`\dG|internet|gprs|[Kk]b|[Mm]b|Gb|lte`, 0, STUDY_JIT_COMPILE)
	m := re.NewMatcherString(`4GKb`, 0)
	if !m.Matches {
		t.Error("The match should be matched")
	}
	m = re.NewMatcherString(`Some value`, 0)
	if m.Matches {
		t.Error("The match should not be matched")
	}
}

func TestStudyNullReturn(t *testing.T) {
	// pcre_study can return NULL without setting an error when no optimization
	// data exists for a pattern. The current code (pcre.go:495) passes the NULL
	// pointer to C.GoBytes, which reads from address 0 — undefined behavior.
	// Go's runtime may catch this as a panic, or it may crash the process.

	patterns := []string{
		"",
		"a",
		"b",
		".*",
		".",
		"^$",
	}

	for _, p := range patterns {
		t.Run(p, func(t *testing.T) {
			re, err := Compile(p, 0)
			if err != nil {
				t.Skipf("compile: %v", err)
			}

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Study on %q panicked (pcre_study likely returned NULL): %v", p, r)
				}
			}()

			err = re.Study(0)
			if err != nil {
				t.Logf("Study error: %v", err)
				return
			}

			t.Logf("has extra=%v (false means pcre_study returned NULL, which is the bug trigger)", re.extra != nil)
		})
	}
}

func TestStudyDataStaysValid(t *testing.T) {
	// pcre_study returns one allocation: [pcre_extra | pcre_study_data],
	// with extra->study_data pointing at the second part. Study() must not
	// leave that pointer targeting the C block it frees.
	re := MustCompile(`(Bel[ao]rus)|(Бел[ао]рус)`, UTF8|CASELESS)
	if err := re.Study(0); err != nil {
		t.Fatal(err)
	}
	if re.extra == nil {
		// This pattern is known to produce study data (TestCompileAndStudy
		// asserts the same); if it stops doing so, the test no longer guards
		// the bug and must be updated with a pattern that does.
		t.Fatal("pcre_study produced no data for this pattern; pick a pattern that has study data")
	}

	// pcre_study lays out its single allocation as [pcre_extra | study_data],
	// so a valid, unfreed block has study_data pointing right behind the
	// struct. Any other value means the block was freed or mangled.
	base := uintptr(unsafe.Pointer(re.extra.p))
	studyData := *(*uintptr)(unsafe.Add(unsafe.Pointer(re.extra.p), studyDataOffset))
	if studyData != base+sizeofPcreExtra {
		t.Errorf("extra.study_data (%#x) does not point right behind pcre_extra (%#x+%d): block freed or corrupted",
			studyData, base, sizeofPcreExtra)
	}

	if !re.NewMatcherString("Беларусь", 0).Matches {
		t.Error("studied regexp failed to match")
	}
}

func TestStudyFreedOnGC(t *testing.T) {
	// Study data (including JIT-compiled code) is C memory; it must be
	// released via pcre_free_study once the Regexp is garbage collected,
	// otherwise every studied pattern leaks for the life of the process.
	before := atomic.LoadUint64(&studiesFreed)

	for i := 0; i < 32; i++ {
		re := MustCompileJIT(`\d+foo`, 0, STUDY_JIT_COMPILE)
		if !re.NewMatcherString("123foo", 0).Matches {
			t.Fatal("should match")
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadUint64(&studiesFreed) == before {
		if time.Now().After(deadline) {
			t.Fatalf("no study data freed after GC: study/JIT memory leaks (freed count still %d)", before)
		}
		runtime.GC()
		time.Sleep(time.Millisecond)
	}
}

func TestStudiedRegexpUsableAfterGC(t *testing.T) {
	// The reverse guarantee: as long as anything (here: a Matcher) still
	// references the Regexp, GC must NOT free the study data.
	m := MustCompileJIT(`(Bel[ao]rus)|(Бел[ао]рус)`, UTF8|CASELESS, STUDY_JIT_COMPILE).
		NewMatcherString("Беларусь", 0)
	runtime.GC()
	runtime.GC()

	if !m.MatchStringWFlags("Беларусь", 0) {
		t.Error("match after GC failed: study data was freed while still referenced")
	}
}

func TestConcurrentMatching(t *testing.T) {
	// The documented contract: once fully constructed (compiled and, if
	// desired, studied), a Regexp may be shared by concurrently matching
	// goroutines, each using its own Matcher. Run under -race, this test
	// validates that promise.
	re := MustCompileJIT(`(Bel[ao]rus)|(Бел[ао]рус)`, UTF8|CASELESS, STUDY_JIT_COMPILE)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var m Matcher
			for i := 0; i < 200; i++ {
				m.ResetString(re, "Беларусь: MTS", 0)
				if !m.Matches {
					t.Error("should match")
					return
				}
				if re.FindString("say Беларусь", 0) == "" {
					t.Error("FindString should match")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestParseFlags(t *testing.T) {
	cases := []struct {
		in          string
		wantPattern string
		wantFlags   int
	}{
		{"abc", "abc", 0},
		{"(?i)abc", "abc", CASELESS},
		{"(?im)abc", "abc", CASELESS | MULTILINE},
		{"(?i)(?m)abc", "abc", CASELESS | MULTILINE},
		{"(?u)abc", "abc", UTF8 | UCP},
		{"(?sUxXDJ)abc", "abc", DOTALL | UNGREEDY | EXTENDED | EXTRA | DOLLAR_ENDONLY | DUPNAMES},
		{"(?:x)abc", "(?:x)abc", 0}, // non-capturing group, not flags
		// Historic behavior, locked in for backward compatibility: any
		// leading "(?letters)" group is consumed and unknown letters are
		// silently ignored — even when the group is really a PCRE construct
		// like (?R). See the ParseFlags doc comment and docs/BUGS.md #8.
		{"(?R)abc", "abc", 0},
		{"(?gi)abc", "abc", CASELESS},
		{"(?i)(?R)abc", "abc", CASELESS},
	}

	for _, c := range cases {
		gotPattern, gotFlags := ParseFlags(c.in)
		if gotPattern != c.wantPattern || gotFlags != c.wantFlags {
			t.Errorf("ParseFlags(%q): got (%q, %#x), want (%q, %#x)",
				c.in, gotPattern, gotFlags, c.wantPattern, c.wantFlags)
		}
	}
}

func TestMatcherPicksUpStudyData(t *testing.T) {
	// Matcher.init has a fast path that skips re-initialization when handed
	// the same compiled pattern. It must not skip when the Regexp has been
	// Studied since — otherwise the study/JIT data is silently ignored.
	re := MustCompile(`(Bel[ao]rus)|(Бел[ао]рус)`, UTF8|CASELESS)

	var m Matcher
	m.Reset(re, []byte("Беларусь"), 0)

	if err := re.Study(STUDY_JIT_COMPILE); err != nil {
		t.Fatal(err)
	}
	if re.extra == nil {
		t.Fatal("study produced no data; the test needs a pattern that has some")
	}

	m.Reset(re, []byte("Беларусь"), 0)
	if m.re.extra == nil {
		t.Error("Matcher kept the pre-Study copy of the Regexp: study/JIT data is silently ignored")
	}
	if !m.Matches {
		t.Error("should match")
	}
}

func TestCompileAndStudy(t *testing.T) {
	re, err := Compile(`(Bel[ao]rus)|(Бел[ао]рус)|(БЕЛ[АО]РУС)|Білорусь`, UTF8|CASELESS)
	if err != nil {
		t.Error("Compile error", err)
	}
	if re.extra != nil {
		t.Error("re.extra should be empty")
	}

	m := re.NewMatcherString("Беларусь: MTS", 0)
	if !m.Matches {
		t.Error("The match should be matched")
	}
	m = re.NewMatcherString("Other value", 0)
	if m.Matches {
		t.Error("The match should not be matched")
	}

	err = re.Study(0)
	if err != nil {
		t.Error("Study error", err)
	}
	if re.extra == nil {
		t.Error("re.extra should not be empty")
	}

	m = re.NewMatcherString("Беларусь: MTS", 0)
	if !m.Matches {
		t.Error("The match should be matched")
	}
	m = re.NewMatcherString("Other value", 0)
	if m.Matches {
		t.Error("The match should not be matched")
	}
}

func BenchmarkStudyAndExec(b *testing.B) {
	// Date check regexp
	re := MustCompile(`^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)(?:0?[1,3-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$`, 0)
	err := re.Study(0)
	if err != nil {
		b.Error("Study error", err)
	}
	subj := []byte(`20-10-2023`)
	m := re.NewMatcher(subj, 0)
	for i := 0; i < b.N; i++ {
		m.MatchWFlags(subj, 0)
		if !m.Matches {
			b.Error("The match should be matched")
		}
	}
}

func BenchmarkExecJIT(b *testing.B) {
	// Date check regexp
	re := MustCompile(`^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)(?:0?[1,3-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$`, 0)
	err := re.Study(STUDY_JIT_COMPILE)
	if err != nil {
		b.Error("Study error", err)
	}
	subj := []byte(`20-10-2023`)
	m := re.NewMatcher(subj, 0)
	for i := 0; i < b.N; i++ {
		m.MatchWFlags(subj, 0)
		if !m.Matches {
			b.Error("The match should be matched")
		}
	}
}

func BenchmarkExecWithoutStudy(b *testing.B) {
	// Date check regexp
	re := MustCompile(`^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)(?:0?[1,3-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$`, 0)
	subj := []byte(`20-10-2023`)
	m := re.NewMatcher(subj, 0)
	for i := 0; i < b.N; i++ {
		m.MatchWFlags(subj, 0)
		if !m.Matches {
			b.Error("The match should be matched")
		}
	}
}

func BenchmarkReplaceAll(b *testing.B) {
	re := MustCompile("foo", 0)
	subj := []byte("food fight fools foo")
	repl := []byte("car")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		re.ReplaceAll(subj, repl, 0)
	}
}

func BenchmarkReplaceAllStringManyMatches(b *testing.B) {
	re := MustCompile("foo", 0)
	subj := strings.Repeat("foo bar baz ", 1000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		re.ReplaceAllString(subj, "car", 0)
	}
}

func BenchmarkReplaceAllString(b *testing.B) {
	re := MustCompile("foo", 0)
	subj := "food fight fools foo"
	repl := "car"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		re.ReplaceAllString(subj, repl, 0)
	}
}

func TestPartial(t *testing.T) {
	re := MustCompile(`^abc`, 0)

	// Check we get a partial match when we should
	m := re.NewMatcherString("ab", PARTIAL_SOFT)
	if !m.Matches {
		t.Error("Failed to find any matches")
	} else if !m.Partial {
		t.Error("The match was not partial")
	}

	// Check we get an exact match when we should
	m = re.NewMatcherString("abc", PARTIAL_SOFT)
	if !m.Matches {
		t.Error("Failed to find any matches")
	} else if m.Partial {
		t.Error("Match was partial but should have been exact")
	}

	m = re.NewMatcher([]byte("ab"), PARTIAL_SOFT)
	if !m.Matches {
		t.Error("Failed to find any matches")
	} else if !m.Partial {
		t.Error("The match was not partial")
	}

	m = re.NewMatcher([]byte("abc"), PARTIAL_SOFT)
	if !m.Matches {
		t.Error("Failed to find any matches")
	} else if m.Partial {
		t.Error("The match was net partial")
	}
}

func TestCaseless(t *testing.T) {
	m := MustCompile("abc", CASELESS).NewMatcherString("Abc", 0)
	if !m.Matches {
		t.Error("CASELESS")
	}
	m = MustCompile("abc", 0).NewMatcherString("Abc", 0)
	if m.Matches {
		t.Error("!CASELESS")
	}
}

func TestNamed(t *testing.T) {
	m := MustCompile("(?<L>a)(?<M>X)*bc(?<DIGITS>\\d*)", 0).
		NewMatcherString("abc12", 0)

	if !m.Matches {
		t.Error("Matches")
	}

	if !m.NamedPresent("L") {
		t.Error("NamedPresent(\"L\")")
	}

	if m.NamedPresent("M") {
		t.Error("NamedPresent(\"M\")")
	}

	if !m.NamedPresent("DIGITS") {
		t.Error("NamedPresent(\"DIGITS\")")
	}

	group, err := m.NamedString("DIGITS")
	if err != nil || group != "12" {
		t.Error("NamedString(\"DIGITS\")")
	}
}

func TestNames(t *testing.T) {
	re := MustCompile("(?<name2>a)(b)(c)(?<n1>d)", 0)
	names := re.CaptureNames()
	if len(names) != 2 {
		t.Error("Names count", len(names))
	}
	if names[0].Name != "n1" {
		t.Error("Names name 1", names[0].Name)
	}
	if names[1].Name != "name2" {
		t.Error("Names name 2", names[1].Name)
	}
	if names[0].Index != 4 {
		t.Error("Names index 1", names[0].Index)
	}
	if names[1].Index != 1 {
		t.Error("Names index 2", names[1].Index)
	}

	// Have no named capturing
	re = MustCompile("(a)bc", 0)
	names = re.CaptureNames()
	if len(names) != 0 {
		t.Error("Names count", len(names))
	}
}

func TestFindIndex(t *testing.T) {
	re := MustCompile("bcd", 0)
	i := re.FindIndex([]byte("abcdef"), 0)
	if i[0] != 1 {
		t.Error("FindIndex start", i[0])
	}
	if i[1] != 4 {
		t.Error("FindIndex end", i[1])
	}
}

func TestInitWithZeroValue(t *testing.T) {
	re1 := MustCompile("foo", 0)
	var re2 Regexp // zero value — ptr is nil

	var m Matcher
	m.init(re1) // m.re.ptr is now non-nil

	// This must not panic: &re2.ptr[0] is guarded alongside the len check.
	m.init(re2)
}

func TestFindAllIndexEmptyMatch(t *testing.T) {
	// An empty-matching pattern causes FindAllIndex to infinite-loop
	// because offset never advances when oVector[0] == oVector[1].
	// We use a goroutine + timeout to safely detect the hang.

	re := MustCompile("", 0) // matches empty string at every position

	done := make(chan struct{})
	go func() {
		defer close(done)
		re.FindAllIndex([]byte("abc"), 0)
	}()

	select {
	case <-done:
		// completed — fix is in place
	case <-time.After(100 * time.Millisecond):
		t.Fatal("FindAllIndex with empty pattern appears to hang (infinite loop)")
	}
}

func TestExtract(t *testing.T) {
	re := MustCompile("b(c)(d)", 0)
	m := re.NewMatcher([]byte("abcdef"), 0)
	i := m.Extract()
	switch {
	case string(i[0]) != "abcdef":
		t.Error("Full line unavailable: ", i[0])
	case string(i[1]) != "c":
		t.Error("First match group no as expected: ", i[1])
	case string(i[2]) != "d":
		t.Error("Second match group no as expected: ", i[2])
	}
}

func TestExtractString(t *testing.T) {
	re := MustCompile("b(c)(d)", 0)
	m := re.NewMatcherString("abcdef", 0)
	i := m.ExtractString()
	switch {
	case i[0] != "abcdef":
		t.Error("Full line unavailable: ", i[0])
	case i[1] != "c":
		t.Error("First match group no as expected: ", i[1])
	case i[2] != "d":
		t.Error("Second match group no as expected: ", i[2])
	}
}

func TestExtractStringAfterBytesMatch(t *testing.T) {
	// Exec ([]byte match) sets SubjectS to "" (pcre.go:523).
	// ExtractString reads from SubjectS directly — slicing an
	// empty string with non-zero offsets panics.

	re := MustCompile("b(c)(d)", 0)
	m := re.NewMatcher([]byte("abcdef"), 0) // calls Exec internally

	// GroupString has a fallback when SubjectS is ""
	if g := m.GroupString(1); g != "c" {
		t.Errorf("GroupString(1): got %q, want %q", g, "c")
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ExtractString panicked: %v", r)
		}
	}()

	_ = m.ExtractString()
}

func TestExtractUnsetGroup(t *testing.T) {
	// Group 1 does not participate in the match; its oVector entries are
	// -1/-1. Extract must return nil for it (as documented), not panic.
	re := MustCompile(`(X)*ab(c)`, 0)
	m := re.NewMatcher([]byte("abc"), 0)
	if !m.Matches {
		t.Fatal("should match")
	}

	ex := m.Extract()
	switch {
	case len(ex) != 3:
		t.Fatal("Extract length", len(ex))
	case string(ex[0]) != "abc":
		t.Error("full match:", ex[0])
	case ex[1] != nil:
		t.Error("unset group should be nil:", ex[1])
	case string(ex[2]) != "c":
		t.Error("group 2:", ex[2])
	}
}

func TestExtractStringUnsetGroup(t *testing.T) {
	re := MustCompile(`(X)*ab(c)`, 0)
	m := re.NewMatcherString("abc", 0)
	if !m.Matches {
		t.Fatal("should match")
	}

	ex := m.ExtractString()
	switch {
	case len(ex) != 3:
		t.Fatal("ExtractString length", len(ex))
	case ex[0] != "abc":
		t.Error("full match:", ex[0])
	case ex[1] != "":
		t.Error("unset group should be empty:", ex[1])
	case ex[2] != "c":
		t.Error("group 2:", ex[2])
	}
}

func TestReplaceAllEmptyMatch(t *testing.T) {
	// A pattern that can match the empty string must not make ReplaceAll
	// loop forever. Expected results follow Perl s///g semantics (verified
	// against perl; note Go's stdlib differs on `o*`: it yields "-f-"
	// because RE2 drops an empty match adjacent to a previous match).
	type tc struct{ pattern, subj, repl, want string }
	tests := []tc{
		{`x*`, "abc", "-", "-a-b-c-"},
		{`o*`, "foo", "-", "-f--"},
		{`o*?`, "foo", "-", "-f-----"},
		{`x*`, "", "-", "-"},
	}

	done := make(chan struct{})
	var got [2][]string
	go func() {
		defer close(done)
		re := Regexp{}
		for _, c := range tests {
			re = MustCompile(c.pattern, 0)
			got[0] = append(got[0], string(re.ReplaceAll([]byte(c.subj), []byte(c.repl), 0)))
			got[1] = append(got[1], re.ReplaceAllString(c.subj, c.repl, 0))
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReplaceAll/ReplaceAllString hang on empty-matching pattern")
	}

	for i, c := range tests {
		if got[0][i] != c.want {
			t.Errorf("ReplaceAll(%q, %q, %q): got %q, want %q", c.pattern, c.subj, c.repl, got[0][i], c.want)
		}
		if got[1][i] != c.want {
			t.Errorf("ReplaceAllString(%q, %q, %q): got %q, want %q", c.pattern, c.subj, c.repl, got[1][i], c.want)
		}
	}
}

func TestReplaceAllKAssertionNoHang(t *testing.T) {
	// \K inside a lookahead makes pcre_exec report a match whose start is
	// AFTER its end: `(?=ab\K)` on "ab" yields ovector [2,0]. Such a match
	// consumes no bytes, so ReplaceAll's loop made no progress and spun
	// forever while growing the result. The reference global-match loop
	// (PCRE2's pcre2demo.c) abandons the run when ovector[0] > ovector[1];
	// ReplaceAll must do the same and return the remaining subject
	// unchanged. (PCRE2 rejects \K in lookarounds at compile time, so v2
	// cannot hit this state at all.)
	re := MustCompile(`(?=ab\K)`, 0)

	done := make(chan struct{})
	var got []byte
	go func() {
		defer close(done)
		got = re.ReplaceAll([]byte("ab"), []byte("<>"), 0)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReplaceAll hangs on \\K-in-lookahead pattern (match start after end)")
	}

	if string(got) != "ab" {
		t.Errorf("ReplaceAll = %q, want %q (run abandoned, subject unchanged)", got, "ab")
	}
}

func TestReplaceAll(t *testing.T) {
	re := MustCompile("foo", 0)
	// Don't change at ends.
	result := re.ReplaceAll([]byte("I like foods."), []byte("car"), 0)
	if string(result) != "I like cards." {
		t.Error("ReplaceAll", result)
	}
	// Change at ends.
	result = re.ReplaceAll([]byte("food fight fools foo"), []byte("car"), 0)
	if string(result) != "card fight carls car" {
		t.Error("ReplaceAll2", result)
	}
}

func TestReplaceAllString(t *testing.T) {
	re := MustCompile("foo", 0)
	tests := []struct {
		subj, repl, want string
	}{
		{"I like foods.", "car", "I like cards."},
		{"food fight fools foo", "car", "card fight carls car"},
		{"no match here", "car", "no match here"},
		{"foo bar", "car", "car bar"},
		{"bar foo", "car", "bar car"},
		{"foofoo", "car", "carcar"},
		{"foo", "car", "car"},
		{"foo and foo and foo", "car", "car and car and car"},
		{"", "car", ""},
		{"foobar", "", "bar"},
	}
	for _, tc := range tests {
		got := re.ReplaceAllString(tc.subj, tc.repl, 0)
		if got != tc.want {
			t.Errorf("ReplaceAllString(%q, %q): got %q, want %q", tc.subj, tc.repl, got, tc.want)
		}
	}
}

func TestGroupMutualRecursion(t *testing.T) {
	re := MustCompile("(.)", 0)
	var m Matcher
	m.init(re)

	done := make(chan struct{})
	go func() {
		m.Group(0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Group(0) did not return (infinite recursion / timeout)")
	}
}
