package compat

// Category 8: UTF-8 subjects with and without the UTF flag. Non-ASCII
// text is written with byte escapes: "h\xc3\xa9llo" is "hello" with an
// e-acute, "\xd1\x89\xd1\x83\xd0\xba\xd0\xb0" is a Cyrillic word,
// "e\xcc\x81x" is e + combining acute + x.
var utfCases = []Case{
	{ID: "utf/dot", Pattern: ".", Subject: "h\xc3\xa9llo", CFlags: []string{"UTF"}},
	{
		ID: "utf/empty-advance", Pattern: "x?", Subject: "h\xc3\xa9llo",
		CFlags: []string{"UTF"}, Repl: "-",
		Known: []string{"D5"}, // v1 stepped bytes and split the e-acute
	},
	{ID: "utf/word-ucp", Pattern: `\w+`, Subject: "\xd1\x89\xd1\x83\xd0\xba\xd0\xb0 word", CFlags: []string{"UTF", "UCP"}},
	{ID: "utf/word-no-ucp", Pattern: `\w+`, Subject: "\xd1\x89\xd1\x83\xd0\xba\xd0\xb0 word", CFlags: []string{"UTF"}},
	{ID: "utf/grapheme", Pattern: `\X`, Subject: "e\xcc\x81x", CFlags: []string{"UTF"}},
	{ID: "utf/invalid-subject", Pattern: "a", Subject: "\xff\xfea", CFlags: []string{"UTF"}},
	{ID: "utf/no-flag-bytes", Pattern: ".", Subject: "h\xc3\xa9llo"},
	{ID: "utf/inline-verb", Pattern: "(*UTF).", Subject: "h\xc3\xa9llo"},
	{ID: "utf/caseless", Pattern: "stra\xc3\x9fe", Subject: "STRA\xc3\x9fE", CFlags: []string{"UTF", "UCP", "CASELESS"}},
}
