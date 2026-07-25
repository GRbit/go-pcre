package compat

// Category 7: empty-width matches driven through FindAllIndex and
// ReplaceAll. Both versions implement the Perl s///g protocol (retry
// NOTEMPTY_ATSTART|ANCHORED after an empty match, then advance); for
// ASCII subjects with no newline convention in play the outputs must
// agree byte for byte.
var emptyCases = []Case{
	{ID: "empty/star", Pattern: "a*", Subject: "bab"},
	{ID: "empty/opt", Pattern: "x?", Subject: "abc"},
	{ID: "empty/nested-star", Pattern: "(a?)*", Subject: "aab"},
	{
		ID: "empty/dollar", Pattern: "$", Subject: "abc",
		Known: []string{"D12"}, // v1 FindAllIndex reported [3,3] twice
	},
	{ID: "empty/group", Pattern: "(?:)", Subject: "ab"},
	{
		ID: "empty/alt-empty-first", Pattern: "|x", Subject: "xy",
		Known: []string{"D12"}, // v1 FindAllIndex skipped the "x" at offset 0
	},
	{
		ID: "empty/alt-bound", Pattern: `\b|x`, Subject: "ax bx",
		Known: []string{"D4"}, // \b half of the alternation sees v1's fake starts
	},
	{
		ID: "empty/star-flags", Pattern: "a*", Subject: "bab",
		EFlags: [][]string{nil, {"NOTEMPTY"}, {"NOTEMPTY_ATSTART"}},
	},
}
