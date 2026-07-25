package compat

// Category 1: basic sanity. These cases must produce zero differences;
// they prove the harness itself introduces no noise.
var basicCases = []Case{
	{ID: "basic/literal", Pattern: "abc", Subject: "xabcy"},
	{ID: "basic/no-match", Pattern: "abc", Subject: "xy"},
	{ID: "basic/quantifiers", Pattern: "a*b+c?", Subject: "aaabbc"},
	{ID: "basic/class", Pattern: "[a-fA-F0-9]+", Subject: "zzdeadBEEF-42zz"},
	{ID: "basic/bounded-repeat", Pattern: "a{2,4}", Subject: "aaaaa"},
	{ID: "basic/dot-empty-subject", Pattern: ".", Subject: ""},
	{ID: "basic/dot-newline", Pattern: ".", Subject: "\n"},
	{ID: "basic/groups", Pattern: "(foo|bar)(baz)?", Subject: "a barbaz b"},
	{ID: "basic/unset-group", Pattern: "(a)|(b)", Subject: "b"},
	{ID: "basic/embedded-nul-subject", Pattern: "b.c", Subject: "ab\x00cd"},
	{
		ID: "basic/caseless", Pattern: "abc", Subject: "xAbCy",
		CFlags: []string{"CASELESS"},
	},
	{
		ID: "basic/exec-flag-variants", Pattern: "^a.", Subject: "ab\nac",
		CFlags: []string{"MULTILINE"},
		EFlags: [][]string{nil, {"NOTBOL"}, {"NOTEMPTY"}, {"ANCHORED"}},
	},
}
