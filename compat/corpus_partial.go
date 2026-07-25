package compat

// Category 16: partial matching. The raw C codes changed (-12 vs -2,
// normalized to PARTIAL by the harness); Matches/Partial and the spans
// must agree.
var partialCases = []Case{
	{ID: "partial/soft", Pattern: "abc", Subject: "ab", EFlags: [][]string{{"PARTIAL_SOFT"}}},
	{ID: "partial/hard", Pattern: "abc", Subject: "ab", EFlags: [][]string{{"PARTIAL_HARD"}}},
	{ID: "partial/digits-hard", Pattern: `\d{4}`, Subject: "123", EFlags: [][]string{{"PARTIAL_HARD"}}},
	{ID: "partial/prefer-partial", Pattern: "a+", Subject: "aaa", EFlags: [][]string{nil, {"PARTIAL_HARD"}}},
	{ID: "partial/no-match", Pattern: "abc", Subject: "xyz", EFlags: [][]string{{"PARTIAL_SOFT"}}},
	{ID: "partial/complete-wins-soft", Pattern: "abc", Subject: "abc", EFlags: [][]string{{"PARTIAL_SOFT"}}},
}
