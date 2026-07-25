package compat

// Category 18: compile errors. Message wording always differs (D3) and
// is suppressed globally; what these cases compare is WHETHER each side
// errors and at which byte offset. One-sided failures are the dialect
// changes under test.
var compileErrCases = []Case{
	{ID: "cerr/unmatched-open", Pattern: "(abc", Subject: "abc"},
	{ID: "cerr/unmatched-close", Pattern: "ab)", Subject: "ab"},
	{ID: "cerr/quantifier-order", Pattern: "a{3,1}", Subject: "aaa"},
	{ID: "cerr/nothing-to-repeat", Pattern: "*a", Subject: "a"},
	{ID: "cerr/class-range", Pattern: "[z-a]", Subject: "b"},
	{ID: "cerr/empty-name", Pattern: "(?<>x)", Subject: "x"},
	{ID: "cerr/trailing-backslash", Pattern: `ab\`, Subject: "ab"},
	{ID: "cerr/bad-brace", Pattern: `\x{}`, Subject: "x"},
	{
		ID: "cerr/bare-x", Pattern: `a\xz`, Subject: "a\x00z",
		// v1: \x with no hex digits after it = NUL, so the pattern is
		// a<NUL>z; v2 (PCRE2 10.45+): compile error.
		Known: []string{"DIALECT:bare-x"},
	},
	{
		// D2 fires via the global rule: NUL byte in the pattern.
		ID: "cerr/nul-in-pattern", Pattern: "a\x00bc", Subject: "za\x00bcz",
	},
}
