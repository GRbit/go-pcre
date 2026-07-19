package pcre

import (
	"strings"
	"testing"
)

// The date-check pattern benchmarks are ported from v1 unchanged and are
// the performance gate of the port: run them in both checkouts on the same
// machine in one session (go test -bench . -benchmem -count=5) and compare
// medians. Reference on x86-64, JIT-enabled PCRE 8.45 vs PCRE2 10.46: JIT
// exec 62 ns/op on both; interpreted exec 201 ns/op (v1) vs 228 ns/op (v2);
// all zero-alloc. A JIT regression against v1 fails the gate.

const dateCheckPattern = `^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)(?:0?[1,3-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$`

func BenchmarkStudyAndExec(b *testing.B) {
	// Date check regexp
	re := MustCompile(dateCheckPattern, 0)
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
	re := MustCompile(dateCheckPattern, 0)
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
	re := MustCompile(dateCheckPattern, 0)
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

func BenchmarkReplaceAllTemplate(b *testing.B) {
	re := MustCompile("foo", 0)
	subj := []byte("food fight fools foo")
	tmpl := []byte("car")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := re.ReplaceAllTemplate(subj, tmpl, 0); err != nil {
			b.Fatal(err)
		}
	}
}
