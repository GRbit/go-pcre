package compat

import "strings"

// Category 17: backtracking limits. Subjects are sized so the default
// match limit (10M in both libraries) trips in well under a second;
// pattern depth stays tiny, so v1's stack-based recursion is safe.
var limitCases = []Case{
	{ID: "limit/nested-quant", Pattern: `(a+)+$`, Subject: strings.Repeat("a", 24) + "!"},
	{ID: "limit/alt-quant", Pattern: `(a|aa)+$`, Subject: strings.Repeat("a", 26) + "b"},
}
