package compat

// Categories 2-4: anchors, word boundaries and lookarounds at iteration
// boundaries. v1 re-sliced the subject between FindAllIndex/ReplaceAll
// iterations, so ^, \A, \b/\B and lookbehind saw a fake subject start at
// every restart; v2 drives PCRE2's native start offset (divergence D4).
// Cases without Known must agree; the annotated ones must not.
var anchorCases = []Case{
	{
		ID: "anchor/caret-findall", Pattern: "^.", Subject: "abc",
		Known: []string{"D4"}, // v1: a,b,c all match; v2: only a
	},
	{
		ID: "anchor/backslash-a", Pattern: `\A.`, Subject: "abc",
		Known: []string{"D4"}, // \A resurrects at v1's fake subject starts
	},
	{ID: "anchor/multiline-words", Pattern: `^\w+$`, Subject: "one\ntwo\nthree", CFlags: []string{"MULTILINE"}},
	{
		ID: "anchor/multiline-caret", Pattern: "^.", Subject: "ab\ncd\nef",
		CFlags: []string{"MULTILINE"},
		Known:  []string{"D4"}, // v1's fake starts made ^ match mid-line even with MULTILINE
	},
	{ID: "anchor/dollar-endonly", Pattern: "abc$", Subject: "abc\n", CFlags: []string{"DOLLAR_ENDONLY"}},
	{ID: "anchor/dollar-plain", Pattern: "abc$", Subject: "abc\n"},
	{ID: "anchor/backslash-z", Pattern: `c\z`, Subject: "abc"},
	{
		ID: "anchor/notbol-noteol", Pattern: "^a|c$", Subject: "abc",
		EFlags: [][]string{nil, {"NOTBOL"}, {"NOTEOL"}, {"NOTBOL", "NOTEOL"}},
	},
}

var boundaryCases = []Case{
	{
		ID: "bound/biss", Pattern: `\Biss`, Subject: "Mississippi",
		Known: []string{"D4"}, // the MIGRATION.md example: 1 vs 2 matches
	},
	{
		ID: "bound/bfoo", Pattern: `\bfoo`, Subject: "foo foofoo foo",
		Known: []string{"D4"}, // v1 sees a fake \b inside "foofoo"
	},
	{
		ID: "bound/notb-dot", Pattern: `\B.`, Subject: "ab ab",
		Known: []string{"D4"},
	},
	{
		ID: "bound/bare-b", Pattern: `\b`, Subject: "hi there",
		// v1 additionally reported one boundary twice and missed the
		// end-of-subject boundary; Perl agrees with v2: <>hi<> <>there<>.
		Known: []string{"D4"},
	},
	{
		ID: "bound/bw", Pattern: `\B\w`, Subject: "abc def",
		Known: []string{"D4"}, // Perl agrees with v2: b,c,e,f
	},
	{ID: "bound/word-caseless", Pattern: `\bcat\b`, Subject: "cat catapult cat", CFlags: []string{"CASELESS"}},
}

var lookaroundCases = []Case{
	{
		ID: "look/behind-a", Pattern: "(?<=a)a", Subject: "aaa",
		Known: []string{"D4"}, // the MIGRATION.md example: 1 vs 2 matches
	},
	{
		ID: "look/behind-digit", Pattern: `(?<=\d)\d`, Subject: "12345",
		Known: []string{"D4"}, // v1: 2 matches; v2: 4
	},
	{ID: "look/ahead-group", Pattern: `(?=(\d+))\w+`, Subject: "abc123"},
	{ID: "look/neg-behind", Pattern: "(?<!x)y", Subject: "xyyy"},
	{ID: "look/var-behind", Pattern: "(?<=a|bc)X", Subject: "aX bcX"},
	{ID: "look/neg-ahead", Pattern: `q(?!u)`, Subject: "quiz qat q"},
	{ID: "look/behind-multiline", Pattern: `(?<=\n)b`, Subject: "abc\nbcd", CFlags: []string{"MULTILINE"}},
}
