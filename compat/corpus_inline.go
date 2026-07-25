package compat

// Category 19 (engine side): inline modifiers through plain Compile,
// plus the one v1 match-time flag that became compile-only in PCRE2.
var inlineCases = []Case{
	{ID: "inline/i", Pattern: "(?i)abc", Subject: "AbC"},
	{ID: "inline/scoped", Pattern: "a(?i:b)c", Subject: "aBc"},
	{ID: "inline/negate", Pattern: "(?i-m)ab", Subject: "AB"},
	{ID: "inline/mid-pattern", Pattern: "ab(?i)cd", Subject: "abCD"},
	{
		ID: "inline/caret-reset", Pattern: "(?^i)x", Subject: "X",
		Known: []string{"DIALECT:new-inline-modifiers"}, // Perl 5.14 syntax, PCRE2-only
	},
	{
		ID: "inline/no-auto-capture", Pattern: "(?n)(a)(b)", Subject: "ab",
		Known: []string{"DIALECT:new-inline-modifiers"},
	},
}

// flagsCases pins the constants-table claim that NO_START_OPTIMIZE moved
// from match time (v1) to compile-only (PCRE2): passing it to pcre2_match
// is an unrecognized option bit.
var flagsCases = []Case{
	{
		ID: "flags/no-start-optimize-match-time", Pattern: "abc", Subject: "xabc",
		EFlags: [][]string{{"NO_START_OPTIMIZE"}},
		Known:  []string{"FLAGS:no-start-optimize-compile-only"},
	},
	{ID: "flags/no-start-optimize-compile-time", Pattern: "abc", Subject: "xabc", CFlags: []string{"NO_START_OPTIMIZE"}},
}
