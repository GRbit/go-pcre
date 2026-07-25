package compat

// Category 5: backreferences and the octal/backreference ambiguity.
// PCRE2 made \8 and \9 unconditional backreferences; PCRE 8.45 treated
// them as literal digits when the pattern had fewer groups.
var backrefCases = []Case{
	{ID: "backref/simple", Pattern: `(a)\1`, Subject: "aa"},
	{ID: "backref/caseless", Pattern: `(ab)\1`, Subject: "abAB", CFlags: []string{"CASELESS"}},
	{
		ID: "backref/eight-literal", Pattern: `(a)\8`, Subject: "a8",
		Known: []string{"DIALECT:backref-digits"}, // v1: literal "8"; v2: compile error
	},
	{
		ID: "backref/nine-literal", Pattern: `\9`, Subject: "9",
		Known: []string{"DIALECT:backref-digits"},
	},
	{ID: "backref/eight-groups", Pattern: `(1)(2)(3)(4)(5)(6)(7)(8)(9)\8`, Subject: "1234567898"},
	{ID: "backref/octal-07", Pattern: `\07`, Subject: "\x07"},
	{ID: "backref/octal-012", Pattern: `\012`, Subject: "\n"},
	{ID: "backref/octal-0", Pattern: `\0`, Subject: "\x00"},
	{ID: "backref/forward", Pattern: `(\2two|(one))+`, Subject: "oneonetwo"},
	{ID: "backref/named-ref", Pattern: `(?<x>ab)\k<x>`, Subject: "abab"},
}
