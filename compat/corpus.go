package compat

// allCases concatenates every corpus category. New category files add
// their slice here.
func allCases() []Case {
	var all []Case
	for _, cat := range [][]Case{
		basicCases,
		anchorCases,
		boundaryCases,
		lookaroundCases,
		emptyCases,
		utfCases,
		newlineCases,
		backrefCases,
		namedCases,
		kEscapeCases,
		compileErrCases,
		caselessCases,
		classCases,
		possessiveCases,
		conditionalCases,
		quoteCases,
		partialCases,
		limitCases,
		inlineCases,
		flagsCases,
	} {
		all = append(all, cat...)
	}

	return all
}
