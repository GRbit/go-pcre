package compat

// Category 11: whitespace and POSIX classes; \x0b is vertical tab, the
// character whose class membership drifted between PCRE generations.
var classCases = []Case{
	{ID: "class/s-vt", Pattern: `\s+`, Subject: "a\x0b\tb"},
	{ID: "class/posix-space", Pattern: `[[:space:]]+`, Subject: "a\x0b\tb"},
	{ID: "class/h", Pattern: `\h+`, Subject: "a \t\x0bb"},
	{ID: "class/v", Pattern: `\v+`, Subject: "a\x0b\nb"},
	{ID: "class/blank", Pattern: `[[:blank:]]+`, Subject: "a \tb\nc"},
	{ID: "class/word-posix", Pattern: `[[:word:]]+`, Subject: "a_1-b"},
	{ID: "class/empty", Pattern: "[]", Subject: "x"},
	{ID: "class/negated-empty", Pattern: "[^]", Subject: "x"},
}
