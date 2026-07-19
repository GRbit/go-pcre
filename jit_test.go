package pcre

import "testing"

func TestStudy(t *testing.T) {
	// Study(0), v1's non-JIT study, is a successful no-op (MIGRATION.md
	// D6): PCRE2 does that work at compile time. JIT flags run
	// pcre2_jit_compile, which is observable through JITCompiled (v1 could
	// silently run JIT-less); the interpreter (NO_JIT) must agree with the
	// JIT code, and studying an already optimized Regexp is an error, as
	// in v1.
	re := MustCompile(`(\d+)foo`, 0)
	if err := re.Study(0); err != nil || re.JITCompiled() {
		t.Fatalf("Study(0): err %v, JITCompiled %v; want a no-op", err, re.JITCompiled())
	}
	if err := re.Study(1 << 30); err == nil {
		t.Error("Study with an unknown option bit should fail")
	}
	if !JITAvailable() {
		if err := re.Study(JIT_COMPLETE); err == nil {
			t.Error("Study(JIT_COMPLETE) on a JIT-less libpcre2 should fail, not silently match interpreted")
		}
		t.Skip("linked libpcre2 has no JIT")
	}
	if err := re.Study(STUDY_JIT_COMPILE); err != nil || !re.JITCompiled() {
		t.Fatalf("Study(JIT_COMPLETE): err %v, JITCompiled %v", err, re.JITCompiled())
	}
	if err := re.Study(JIT_COMPLETE); err == nil {
		t.Error("second Study should return an error")
	}
	for _, flags := range []int{0, NO_JIT} {
		if m := re.NewMatcherString("123foo", flags); !m.Matches || m.GroupString(1) != "123" {
			t.Errorf("match flags %#x: Matches=%v, group 1 %q, want 123", flags, m.Matches, m.GroupString(1))
		}
		if re.NewMatcherString("Some value", flags).Matches {
			t.Errorf("match flags %#x: should not match", flags)
		}
	}

	// CompileJIT demands the complete-compile flag (v1 contract), and
	// MustCompileJIT panics on that error.
	if _, err := CompileJIT(`\d`, 0, JIT_PARTIAL_SOFT); err == nil {
		t.Error("CompileJIT without JIT_COMPLETE should return an error")
	}
	if _, err := CompileJIT(`\d`, 0, JIT_COMPLETE|1<<30); err == nil {
		t.Error("CompileJIT with an unknown JIT option bit should return the Study error")
	}
	defer func() {
		if recover() == nil {
			t.Error("MustCompileJIT without JIT_COMPLETE should panic")
		}
	}()
	MustCompileJIT(`\d`, 0, 0)
}

func TestPartialJIT(t *testing.T) {
	// Partial matching under JIT needs the corresponding partial JIT mode
	// compiled in; PCRE2 falls back to the interpreter otherwise. Either
	// way the result must equal the interpreted one.
	re := MustCompile(`^abc`, 0)
	if err := re.Study(JIT_COMPLETE | JIT_PARTIAL_SOFT); err != nil {
		if !JITAvailable() {
			t.Skip("linked libpcre2 has no JIT")
		}
		t.Fatal("Study:", err)
	}
	m := re.NewMatcherString("ab", PARTIAL_SOFT)
	if !m.Matches || !m.Partial {
		t.Error("expected a partial match under JIT partial mode")
	}
}
