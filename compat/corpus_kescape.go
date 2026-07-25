package compat

// Category 14: \K (reset match start). PCRE2 10.38+ rejects \K inside
// lookarounds; \K also exercises v2's non-empty-match-without-progress
// iteration branch.
var kEscapeCases = []Case{
	{ID: "kesc/basic", Pattern: `foo\Kbar`, Subject: "foobar foobar"},
	{ID: "kesc/short", Pattern: `a\Kb`, Subject: "abab"},
	{ID: "kesc/empty-after", Pattern: `x\K`, Subject: "xx"},
	{
		ID: "kesc/in-lookahead", Pattern: `(?=ab\K)`, Subject: "ab",
		Known: []string{"DIALECT:k-lookaround"}, // v2 (10.38+): compile error
	},
	{ID: "kesc/alternation", Pattern: `a\Kb|c`, Subject: "abcab"},
}
