package compat

import "strings"

// classify tags one diff with the divergence that explains it, or ""
// when it is unexplained. Global rules recognize divergences that are
// mechanical consequences of the migration (documented in MIGRATION.md)
// regardless of the pattern; everything else falls back to the case's
// Known annotation.
func classify(c Case, r1, r2 *Record, d Diff) string {
	switch {
	// D2: NUL bytes in the pattern compile in v2, failed in v1.
	case d.Field == "compile-ok" &&
		strings.Contains(c.Pattern, "\x00") && !r1.CompileOK && r2.CompileOK:
		return "D2"

	// D1: v1 panicked inside checkMatch, v2 stored a MatchError.
	case r1.Panic != "" && r2.Panic == "" && r2.MatchErr != "" &&
		(d.Field == "panic" || d.Field == "match-err" || d.Field == "matches"):
		return "D1"

	// D11: duplicate-name lookups fail typed in v2; v1 silently resolved
	// the name to an arbitrary one of the duplicate groups (binary-search
	// landing point), returning its value with no error.
	case strings.HasPrefix(d.Field, "named:") &&
		strings.Contains(d.V2, "err=NONUNIQUE") && !strings.Contains(d.V1, "err=NONUNIQUE"):
		return "D11"
	}

	if len(c.Known) > 0 {
		return strings.Join(c.Known, "+")
	}

	return ""
}
