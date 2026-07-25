package compat

import (
	"sort"
	"strings"
	"testing"

	pcre1 "github.com/GRbit/go-pcre"
	pcre2 "github.com/GRbit/go-pcre/v2"
)

// flagNames decomposes a flags word into the symbolic names of table m.
// Zero-valued entries (v2's EXTRA) decompose to nothing by construction.
func flagNames(m map[string]int, f int) []string {
	var names []string
	for name, bit := range m {
		if bit != 0 && f&bit == bit {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	return names
}

// TestParseFlagsParity runs the same inputs through both ParseFlags
// implementations and compares the remaining pattern plus the SYMBOLIC
// flag decomposition (raw values differ by design). The one asymmetry is
// the letter X: v1 maps it to a real EXTRA bit, v2's EXTRA is 0 (D8), so
// X contributes nothing on the v2 side; EXTRA is excluded from the
// comparison for that reason.
func TestParseFlagsParity(t *testing.T) {
	inputs := []string{
		"(?i)abc", "(?im)x", "(?gi)x", "(?R)x", "(*UTF)x", "(?i:x)y",
		"(?iX)x", "(?u)x", "(?i)(?m)z", "x(?i)y", "(?D)a$", "plain",
	}
	for _, in := range inputs {
		p1, f1 := pcre1.ParseFlags(in)
		p2, f2 := pcre2.ParseFlags(in)
		if p1 != p2 {
			t.Errorf("ParseFlags(%q): remaining pattern differs: v1 %q, v2 %q", in, p1, p2)

			continue
		}
		n1 := flagNames(cFlags1, f1&^pcre1.EXTRA)
		n2 := flagNames(cFlags2, f2)
		if strings.Join(n1, ",") != strings.Join(n2, ",") {
			t.Errorf("ParseFlags(%q): flags differ: v1 %v, v2 %v", in, n1, n2)
		}
	}
}

// TestStudyParity pins the Study behavior matrix documented in D6:
// Study(0) succeeds on both sides; a second JIT Study fails on both
// sides with the same message; and Study(0)-then-JIT works in v2 while
// v1 can refuse it when the first study produced data.
func TestStudyParity(t *testing.T) {
	re1 := pcre1.MustCompile("abc", 0)
	if err := re1.Study(0); err != nil {
		t.Errorf("v1 Study(0): %v", err)
	}
	re2 := pcre2.MustCompile("abc", 0)
	if err := re2.Study(0); err != nil {
		t.Errorf("v2 Study(0): %v", err)
	}

	re1b := pcre1.MustCompile("abc", 0)
	if err := re1b.Study(pcre1.STUDY_JIT_COMPILE); err != nil {
		t.Fatalf("v1 first JIT Study: %v", err)
	}
	err1 := re1b.Study(pcre1.STUDY_JIT_COMPILE)
	re2b := pcre2.MustCompile("abc", 0)
	if err := re2b.Study(pcre2.JIT_COMPLETE); err != nil {
		t.Fatalf("v2 first JIT Study: %v", err)
	}
	err2 := re2b.Study(pcre2.JIT_COMPLETE)
	if err1 == nil || err2 == nil {
		t.Fatalf("double JIT Study: want errors on both sides, got v1=%v v2=%v", err1, err2)
	}
	if err1.Error() != err2.Error() {
		t.Errorf("double JIT Study error text differs: v1 %q, v2 %q", err1, err2)
	}

	// Study(0) then JIT: v2 always allows it (Study(0) was a no-op); v1
	// refuses when the plain study produced data ([ab]c yields a
	// start-byte bitmap, so it does here). Documented in D6.
	re1c := pcre1.MustCompile("[ab]c", 0)
	if err := re1c.Study(0); err != nil {
		t.Fatalf("v1 Study(0) on [ab]c: %v", err)
	}
	if err := re1c.Study(pcre1.STUDY_JIT_COMPILE); err == nil {
		t.Log("v1 allowed Study(0) then JIT Study; D6's note about v1 refusing no longer holds")
	}
	re2c := pcre2.MustCompile("[ab]c", 0)
	if err := re2c.Study(0); err != nil {
		t.Fatalf("v2 Study(0) on [ab]c: %v", err)
	}
	if err := re2c.Study(pcre2.JIT_COMPLETE); err != nil {
		t.Errorf("v2 Study(0) then JIT Study: %v, want nil (Study(0) is a no-op, D6)", err)
	}
}
