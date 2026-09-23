package compat

import (
	"slices"
	"strings"
)

// knownFields lists, per divergence tag, the record fields whose diffs the
// tag can explain. A case annotation therefore vouches only for the
// fields its divergence touches: a diff in any other field of the same
// case stays unexplained and fails the run, instead of being absorbed by
// an unrelated tag. Tags absent here are the DIALECT:* and FLAGS:*
// families, which alter compile results and everything downstream and so
// may explain any field.
var knownFields = map[string][]string{
	"D3":  {"compile-offset"},
	"D4":  {"find-all", "replace-all"},
	"D5":  {"find-all", "replace-all"},
	"D12": {"find-all", "replace-all"},
}

// explains reports whether tag can account for a diff in field. Parity
// fields (one side's byte API against its own string API) are never
// explained by an annotation: the two APIs must agree on both sides.
func explains(tag, field string) bool {
	if strings.Contains(field, "-parity:") {
		return false
	}
	if fields, ok := knownFields[tag]; ok {
		return slices.Contains(fields, field)
	}

	return strings.HasPrefix(tag, "DIALECT:") || strings.HasPrefix(tag, "FLAGS:")
}

// missingKnown returns the annotated tags that explained no diff. Each
// tag must reproduce on its own: a diff explained by another tag of the
// same case, or by a global rule (D1, D2, D11), does not vouch for it, so
// a stale annotation cannot hide behind an unrelated divergence.
func missingKnown(known []string, fired map[string]bool) []string {
	var missing []string
	for _, tag := range known {
		if !fired[tag] {
			missing = append(missing, tag)
		}
	}

	return missing
}

// classify tags one diff with the divergence that explains it, or ""
// when it is unexplained. Global rules recognize divergences that are
// mechanical consequences of the migration (documented in MIGRATION.md)
// regardless of the pattern; everything else falls back to the case's
// Known annotation, restricted to the fields each tag can explain.
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

	var tags []string
	for _, k := range c.Known {
		if explains(k, d.Field) {
			tags = append(tags, k)
		}
	}

	return strings.Join(tags, "+")
}
