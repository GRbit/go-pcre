package compat

// Category 13: conditionals and recursion. These letter-heavy constructs
// are exactly what the lenient ParseFlags mangles, so they go through
// plain Compile here.
var conditionalCases = []Case{
	{ID: "cond/group-set", Pattern: "(x)?(?(1)a|b)", Subject: "xa"},
	{ID: "cond/group-unset", Pattern: "(x)?(?(1)a|b)", Subject: "b"},
	{ID: "cond/assert", Pattern: "^(?(?=a)ab|cd)$", Subject: "ab"},
	{ID: "cond/assert-else", Pattern: "^(?(?=a)ab|cd)$", Subject: "cd"},
	{ID: "cond/recursion", Pattern: `\((?:[^()]|(?R))*\)`, Subject: "x(a(b)c)y"},
	{ID: "cond/named-recurse", Pattern: `(?<w>a)(?&w)`, Subject: "aa"},
	{ID: "cond/named-cond", Pattern: `(?<w>x)?(?(<w>)y|n)`, Subject: "xy"},
	{ID: "cond/named-cond-unset", Pattern: `(?<w>x)?(?(<w>)y|n)`, Subject: "n"},
}
