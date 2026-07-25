package compat

// Category 15: \Q..\E quoting and the \N forms.
var quoteCases = []Case{
	{ID: "quote/literal", Pattern: `\Qa.b*\E`, Subject: "xa.b*y"},
	{ID: "quote/empty", Pattern: `\Q\Ex`, Subject: "x"},
	{ID: "quote/quantified", Pattern: `a\Q+\E+`, Subject: "a++"},
	{ID: "quote/n-any", Pattern: `\N`, Subject: "a\n"},
	{
		ID: "quote/n-codepoint", Pattern: `\N{U+0041}`, Subject: "A",
		CFlags: []string{"UTF"},
		Known:  []string{"DIALECT:n-codepoint"}, // v1: compile error; v2: matches "A"
	},
	{
		ID: "quote/n-name", Pattern: `\N{LATIN SMALL LETTER A}`, Subject: "a",
		Known: []string{"D3"}, // both fail, but at offset 1 (v1) vs 2 (v2)
	},
}
