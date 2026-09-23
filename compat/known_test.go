package compat

import "testing"

func TestClassifyRestrictsKnownToItsFields(t *testing.T) {
	// A Known annotation vouches only for the fields its divergence
	// touches; anything else on the same case must stay unexplained.
	ok := &Record{CompileOK: true}
	d4 := Case{ID: "t/d4", Known: []string{"D4"}}
	dialect := Case{ID: "t/dialect", Known: []string{"DIALECT:x"}}

	for _, tc := range []struct {
		c     Case
		field string
		want  string
	}{
		{d4, "find-all", "D4"},
		{d4, "replace-all", "D4"},
		{d4, "groups", ""},
		{d4, "extract", ""},
		{d4, "compile-offset", ""},
		{d4, "v2-parity:find-all", ""},
		{dialect, "groups", "DIALECT:x"},
		{dialect, "compile-ok", "DIALECT:x"},
		{dialect, "v1-parity:extract", ""},
		{Case{ID: "t/typo", Known: []string{"D99"}}, "find-all", ""},
	} {
		got := classify(tc.c, ok, ok, Diff{Field: tc.field, V1: "a", V2: "b"})
		if got != tc.want {
			t.Errorf("%s: classify(%s) = %q, want %q", tc.c.ID, tc.field, got, tc.want)
		}
	}
}
