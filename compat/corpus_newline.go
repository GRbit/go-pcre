package compat

// Category 9: newline conventions selected with in-pattern verbs (the
// replacement for v1's NEWLINE_*/BSR_* flags, divergence D7) and the
// CRLF-atomic empty-match advance (divergence D5).
var newlineCases = []Case{
	{ID: "nl/crlf-caret", Pattern: "(*CRLF)^.", Subject: "a\r\nb", CFlags: []string{"MULTILINE"}},
	{
		ID: "nl/crlf-empty-advance", Pattern: "(*CRLF)x?", Subject: "a\r\nb", Repl: "-",
		Known: []string{"D5"}, // v2 skips the CRLF pair atomically, v1 split it
	},
	{
		ID: "nl/anycrlf-dollar", Pattern: "(*ANYCRLF)$", Subject: "a\rb\nc\r\nd",
		CFlags: []string{"MULTILINE"},
		// v1: duplicate empty matches (D12), a fake match between \r and
		// \n from re-slicing (D4), and ReplaceAll split the CRLF (D5).
		Known: []string{"D4", "D5", "D12"},
	},
	{ID: "nl/any-caret", Pattern: "(*ANY)^.", Subject: "a\rb\x0cc", CFlags: []string{"MULTILINE"}},
	{ID: "nl/bsr-default", Pattern: `\R`, Subject: "a\r\nb\nc"},
	{ID: "nl/bsr-nel-byte", Pattern: `\R`, Subject: "a\x85b"},
	{ID: "nl/bsr-anycrlf", Pattern: `(*BSR_ANYCRLF)\R`, Subject: "a\x85b\r\nc"},
	{
		ID: "nl/crlf-dollar-replace", Pattern: "(*CRLF)$", Subject: "a\r\nb",
		CFlags: []string{"MULTILINE"}, Repl: "-",
		Known: []string{"D12"}, // duplicate empty matches in v1's FindAllIndex
	},
}
