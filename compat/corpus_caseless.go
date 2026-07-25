package compat

// Category 10: case-insensitive matching, including Unicode case rules
// that changed in PCRE2 10.45 (Lu/Ll/Lt unified as Lc under CASELESS).
// Escapes: \xcf\x83 = small sigma, \xce\xa3 = capital sigma, \xcf\x82 =
// final sigma, \xe2\x84\xaa = Kelvin sign, \xc4\xb0 = capital I with dot.
var caselessCases = []Case{
	{ID: "case/ascii", Pattern: "[a-z]+", Subject: "AbC", CFlags: []string{"CASELESS"}},
	{ID: "case/sigma", Pattern: "\xcf\x83+", Subject: "\xce\xa3\xcf\x83\xcf\x82", CFlags: []string{"UTF", "UCP", "CASELESS"}},
	{ID: "case/kelvin", Pattern: "k", Subject: "\xe2\x84\xaa", CFlags: []string{"UTF", "UCP", "CASELESS"}},
	{
		ID: "case/prop-lu", Pattern: `\p{Lu}`, Subject: "a",
		CFlags: []string{"UTF", "UCP", "CASELESS"},
		Known:  []string{"DIALECT:caseless-lc"}, // 10.45+: caseless \p{Lu} matches lowercase
	},
	{ID: "case/dotted-i", Pattern: "\xc4\xb0", Subject: "i", CFlags: []string{"UTF", "UCP", "CASELESS"}},
	{ID: "case/backref", Pattern: `(ab)\1`, Subject: "ABab", CFlags: []string{"CASELESS"}},
}
