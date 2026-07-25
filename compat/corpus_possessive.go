package compat

// Category 12: possessive quantifiers and atomic groups (PCRE2's
// auto-possessification could in principle differ; results must not).
var possessiveCases = []Case{
	{ID: "poss/plusplus", Pattern: "a++b", Subject: "aaab"},
	{ID: "poss/no-backtrack", Pattern: "a++ab", Subject: "aaab"},
	{ID: "poss/atomic", Pattern: "(?>a+)a", Subject: "aaaa"},
	{ID: "poss/digits", Pattern: `\d++\.`, Subject: "123."},
	{ID: "poss/bounded", Pattern: "a{2,}+b", Subject: "aaab"},
	{ID: "poss/auto", Pattern: "a+b", Subject: "aaab"},
	{ID: "poss/star-atomic", Pattern: `(?>\d*)\d`, Subject: "123"},
}
