package pcre

import (
	"errors"
	"strings"
	"testing"
)

// cyrBelarusMixed is "bELARUS" with a soft sign in mixed case (UTF-8 byte
// escapes, see matcher_test.go): only case folding matches it against
// cyrBelarusPattern.
const cyrBelarusMixed = "\xd0\xb1\xd0\x95\xd0\x9b\xd0\x90\xd0\xa0\xd0\xa3\xd0\xa1\xd0\xac"

func TestParseFlags(t *testing.T) {
	// ParseFlags keeps v1's lenient semantics: every leading "(?letters)"
	// group is consumed and unknown letters are silently ignored, even
	// when the group is really a PCRE construct like (?R). ParseFlagsStrict
	// leaves a group containing any unknown letter to the engine and stops
	// there. X (v1 EXTRA) maps to no flag bits: PCRE2 is strict by default
	// (MIGRATION.md D8).
	const all = DOTALL | UNGREEDY | EXTENDED | EXTRA | DOLLAR_ENDONLY | DUPNAMES
	cases := []struct {
		in           string
		lenient      string
		lenientFlags int
		strict       string
		strictFlags  int
	}{
		{"abc", "abc", 0, "abc", 0},
		{"(?i)abc", "abc", CASELESS, "abc", CASELESS},
		{"(?im)abc", "abc", CASELESS | MULTILINE, "abc", CASELESS | MULTILINE},
		{"(?i)(?m)abc", "abc", CASELESS | MULTILINE, "abc", CASELESS | MULTILINE},
		{"(?u)abc", "abc", UTF8 | UCP, "abc", UTF8 | UCP},
		{"(?sUxXDJ)abc", "abc", all, "abc", all},
		{"(?:x)abc", "(?:x)abc", 0, "(?:x)abc", 0}, // non-capturing group, not flags
		{"(?R)abc", "abc", 0, "(?R)abc", 0},
		{"(?gi)abc", "abc", CASELESS, "(?gi)abc", 0},
		{"(?i)(?R)abc", "abc", CASELESS, "(?R)abc", CASELESS},
		{"(?R)(?i)abc", "abc", CASELESS, "(?R)(?i)abc", 0},
	}

	for _, c := range cases {
		if p, f := ParseFlags(c.in); p != c.lenient || f != c.lenientFlags {
			t.Errorf("ParseFlags(%q) = (%q, %#x), want (%q, %#x)", c.in, p, f, c.lenient, c.lenientFlags)
		}
		if p, f := ParseFlagsStrict(c.in); p != c.strict || f != c.strictFlags {
			t.Errorf("ParseFlagsStrict(%q) = (%q, %#x), want (%q, %#x)", c.in, p, f, c.strict, c.strictFlags)
		}
	}
}

func TestCompileParse(t *testing.T) {
	re := MustCompileParse("(?i)abc")
	if !re.MatchStringWFlags("xABCy", 0) {
		t.Error("(?i)abc should match xABCy caselessly")
	}

	re = MustCompileParseJIT("(?iu)"+cyrBelarusPattern, JIT_COMPLETE)
	if !re.MatchStringWFlags(cyrBelarusMixed, 0) {
		t.Error("(?iu) pattern should match caselessly in UTF mode")
	}

	// Errors keep the v1 message prefix for callers that match on it, but
	// the *CompileError behind it (message, offset) is reachable with
	// errors.As instead of being thrown away (MIGRATION.md D13).
	for name, compile := range map[string]func(string) (Regexp, error){
		"CompileParse":    CompileParse,
		"CompileParseJIT": func(p string) (Regexp, error) { return CompileParseJIT(p, JIT_COMPLETE) },
	} {
		_, err := compile("(?i)a(")
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if !strings.HasPrefix(err.Error(), "can't compile/study pcre regexp: pattern='a(' flags=") {
			t.Errorf("%s: message lost the v1 prefix: %q", name, err)
		}
		var cErr *CompileError
		if !errors.As(err, &cErr) {
			t.Errorf("%s: error %q does not wrap *CompileError", name, err)

			continue
		}
		if cErr.Offset != 2 {
			t.Errorf("%s: CompileError.Offset = %d, want 2", name, cErr.Offset)
		}
	}

	for name, must := range map[string]func(){
		"MustCompileParse":    func() { MustCompileParse("(?i)(") },
		"MustCompileParseJIT": func() { MustCompileParseJIT("(?i)(", JIT_COMPLETE) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s of an invalid pattern should panic", name)
				}
			}()
			must()
		}()
	}
}

func TestCompileParseStrict(t *testing.T) {
	re, err := CompileParseStrict("(?i)abc")
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchStringWFlags("xABCy", 0) {
		t.Error("(?i)abc should match xABCy caselessly")
	}

	// Perl-faithful failure: (?gi) reaches the engine and is rejected
	// there with a real *CompileError (historic CompileParse silently
	// turned it into CASELESS).
	_, err = CompileParseStrict("(?gi)abc")
	var cErr *CompileError
	if !errors.As(err, &cErr) {
		t.Errorf("CompileParseStrict((?gi)abc): err = %v, want *CompileError", err)
	}

	// (?R) survives as recursion syntax and compiles.
	if _, err = CompileParseStrict(`a(?R)?b`); err != nil {
		t.Errorf("a(?R)?b should compile as recursion: %v", err)
	}
}

func TestLeadingFlagGroup(t *testing.T) {
	// The byte scanner must accept exactly what v1's `^\(\?[a-zA-Z]+?\)`
	// regexp accepted: "(?" + one or more ASCII letters + ")".
	for in, want := range map[string]int{
		"":            0,
		"(?)":         0,
		"(?i":         0,
		"(?i)":        4,
		"(?imsx)abc":  7,
		"(?:x)":       0,
		"(?R)(?i)":    4,
		"(?1)":        0,
		"(?i-m)":      0,
		"x(?i)":       0,
		"(?\xc3\xa9)": 0, // non-ASCII letter: not a flag letter
	} {
		if got := leadingFlagGroup(in); got != want {
			t.Errorf("leadingFlagGroup(%q) = %d, want %d", in, got, want)
		}
	}
}
