package compat

// 33 and 129 letter group names: PCRE 8.45 capped names at 32
// characters, PCRE2 at 128.
const (
	name33  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	name129 = name33 + name33 + name33 + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// Category 6: named capture groups, duplicate names, name limits.
var namedCases = []Case{
	{ID: "named/basic", Pattern: `(?<user>\w+)@(?<host>\w+)`, Subject: "joe@example"},
	{ID: "named/unset", Pattern: `(?<a>x)|(?<b>y)`, Subject: "y"},
	{
		// D11 fires via the global rule: v1 reports the duplicate name as
		// unknown, v2 as ErrNonUniqueName.
		ID: "named/dupnames", Pattern: `(?<n>a)|(?<n>b)`, Subject: "b",
		CFlags: []string{"DUPNAMES"},
	},
	{ID: "named/inline-dupnames", Pattern: `(?J)(?<n>a)|(?<n>b)`, Subject: "a"},
	{
		ID: "named/len-33", Pattern: "(?<" + name33 + ">x)", Subject: "x",
		Known: []string{"DIALECT:name-length"}, // v1: too long (max 32); v2: fine (max 128)
	},
	{ID: "named/len-129", Pattern: "(?<" + name129 + ">x)", Subject: "x"},
	{
		ID: "named/branch-reset-two-names", Pattern: `(?|(?<a>A)|(?<b>B))`, Subject: "B",
		Known: []string{"DIALECT:branch-reset-names"}, // v2 rejects two names for one group number
	},
	{ID: "named/python-syntax", Pattern: `(?P<py>x)(?P=py)`, Subject: "xx"},
	{ID: "named/digit-start", Pattern: `(?<1a>x)`, Subject: "x"},
}
