package pcre

import (
	"testing"
	"time"
)

// replaceCases are Perl-verified (perl -e 's///g') expectations shared by
// the ReplaceAll and pcre2_substitute comparisons. Go's stdlib differs on
// `o*`: RE2 drops an empty match adjacent to a previous match ("-f-").
// With an explicit LF newline convention the empty-match advance is per
// character (Perl parity); a CRLF-aware convention skips CRLF as one unit,
// which is PCRE2's canonical protocol (pcre2_substitute, 10.47+'s
// pcre2_next_match) and an intentional, documented divergence from Perl,
// which has no newline-convention concept (MIGRATION.md D5).
var replaceCases = []struct {
	pattern, subject, repl string
	flags                  int
	want                   string
}{
	{"foo", "I like foods.", "car", 0, "I like cards."},
	{"foo", "food fight fools foo", "car", 0, "card fight carls car"},
	{"foo", "no match here", "car", 0, "no match here"},
	{"foo", "foofoo", "car", 0, "carcar"},
	{"foo", "", "car", 0, ""},
	{"foo", "foobar", "", 0, "bar"},
	{`x*`, "abc", "-", 0, "-a-b-c-"},
	{`o*`, "foo", "-", 0, "-f--"},
	{`o*?`, "foo", "-", 0, "-f-----"},
	{`x*`, "", "-", 0, "-"},
	{`x*`, "a\xc3\xa9", "-", UTF, "-a-\xc3\xa9-"},
	{`(*LF)x*`, "a\r\nb", "-", 0, "-a-\r-\n-b-"},
	{`(*ANYCRLF)x*`, "a\r\nb", "-", 0, "-a-\r\n-b-"},
}

func TestReplaceAll(t *testing.T) {
	// A watchdog turns an infinite loop on an empty-matching pattern into
	// a failure.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, c := range replaceCases {
			re := MustCompile(c.pattern, c.flags)
			if got := string(re.ReplaceAll([]byte(c.subject), []byte(c.repl), 0)); got != c.want {
				t.Errorf("ReplaceAll(%q, %q, %q) = %q, want %q", c.pattern, c.subject, c.repl, got, c.want)
			}
			if got := re.ReplaceAllString(c.subject, c.repl, 0); got != c.want {
				t.Errorf("ReplaceAllString(%q, %q, %q) = %q, want %q", c.pattern, c.subject, c.repl, got, c.want)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReplaceAll appears to hang on an empty-matching pattern")
	}
}

func TestReplaceAllAgainstSubstitute(t *testing.T) {
	// The Go replace loop and pcre2_substitute(GLOBAL) implement the same
	// canonical protocol, so they must agree on the whole table. The
	// replacements contain no '$', so they are valid templates verbatim.
	for _, c := range replaceCases {
		re := MustCompile(c.pattern, c.flags)
		subst, err := re.ReplaceAllTemplateString(c.subject, c.repl, 0)
		if err != nil {
			t.Errorf("substitute(%q, %q): %v", c.pattern, c.subject, err)

			continue
		}
		if loop := re.ReplaceAllString(c.subject, c.repl, 0); loop != subst {
			t.Errorf("divergence on (%q, %q, %q): loop %q, substitute %q",
				c.pattern, c.subject, c.repl, loop, subst)
		}
	}
}

func TestReplaceAllTemplate(t *testing.T) {
	// New v2 API on pcre2_substitute: $1/${name} replacement templates.
	re := MustCompile(`(?<user>\w+)@(?<host>\w+)`, 0)

	got, err := re.ReplaceAllTemplateString("bob@example or eve@evil", "$2:$1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := "example:bob or evil:eve"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	got, err = re.ReplaceAllTemplateString("bob@example", "${host}/${user}", 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := "example/bob"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// Unset groups substitute as empty (PCRE2_SUBSTITUTE_UNSET_EMPTY is
	// always on: Go template expectations).
	re = MustCompile(`(a)|(b)`, 0)
	got, err = re.ReplaceAllTemplateString("ab", "[$1$2]", 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := "[a][b]"; got != want {
		t.Errorf("unset-empty: got %q, want %q", got, want)
	}

	// A syntactically bad template is an error, not a panic.
	if _, err = re.ReplaceAllTemplateString("ab", "$", 0); err == nil {
		t.Error("bad template should return an error")
	}

	// A replacement far larger than the subject exercises the
	// OVERFLOW_LENGTH retry path.
	re = MustCompile("a", 0)
	long := ""
	for i := 0; i < 20; i++ {
		long += "0123456789"
	}
	got, err = re.ReplaceAllTemplateString("aaa", long, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3*len(long) {
		t.Errorf("overflow retry: got len %d, want %d", len(got), 3*len(long))
	}

	// []byte variant.
	reB := MustCompile(`(\d+)`, 0)
	gotB, err := reB.ReplaceAllTemplate([]byte("x1y22z"), []byte("<$1>"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := "x<1>y<22>z"; string(gotB) != want {
		t.Errorf("bytes: got %q, want %q", gotB, want)
	}
}
