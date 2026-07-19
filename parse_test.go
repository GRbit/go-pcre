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
	// when the group is really a PCRE construct like (?R). X (v1 EXTRA)
	// maps to no flag bits: PCRE2 is strict by default (MIGRATION.md D8).
	const all = DOTALL | UNGREEDY | EXTENDED | EXTRA | DOLLAR_ENDONLY | DUPNAMES
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
		{"(?sUxXDJ)abc", "abc", all},
		{"(?:x)abc", "(?:x)abc", 0}, // non-capturing group, not flags
		{"(?R)abc", "abc", 0},
		{"(?gi)abc", "abc", CASELESS},
		{"(?i)(?R)abc", "abc", CASELESS},
		{"(?R)(?i)abc", "abc", CASELESS},
	}

	for _, c := range cases {
		if p, f := ParseFlags(c.in); p != c.wantPattern || f != c.wantFlags {
			t.Errorf("ParseFlags(%q) = (%q, %#x), want (%q, %#x)", c.in, p, f, c.wantPattern, c.wantFlags)
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
