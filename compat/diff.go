package compat

import (
	"fmt"
	"sort"
	"strings"
)

// Diff is one field where v1 and v2 disagree for a (case, axis) run.
type Diff struct {
	Field string
	V1    string
	V2    string
}

func joined(ss []string) string { return "[" + strings.Join(ss, " ") + "]" }

// diffRecords compares two normalized records field by field.
//
// Compile-error message wording is never compared: it always differs
// between the libraries (MIGRATION.md D3). When both sides fail to
// compile, only the error offset is comparable; when exactly one side
// fails, the single compile-ok diff subsumes everything downstream.
func diffRecords(r1, r2 *Record) []Diff {
	var ds []Diff
	add := func(field, a, b string) {
		if a != b {
			ds = append(ds, Diff{Field: field, V1: a, V2: b})
		}
	}

	if r1.CompileOK != r2.CompileOK {
		return []Diff{{
			Field: "compile-ok",
			V1:    fmt.Sprintf("%v (%s)", r1.CompileOK, r1.CompileMsg),
			V2:    fmt.Sprintf("%v (%s)", r2.CompileOK, r2.CompileMsg),
		}}
	}
	if !r1.CompileOK {
		// Only the numeric offset is comparable; the messages (kept for
		// context when the offsets disagree) always differ per D3.
		if r1.CompileOffset != r2.CompileOffset {
			add("compile-offset",
				fmt.Sprintf("%d (%s)", r1.CompileOffset, r1.CompileMsg),
				fmt.Sprintf("%d (%s)", r2.CompileOffset, r2.CompileMsg))
		}

		return ds
	}

	add("groups", fmt.Sprint(r1.Groups), fmt.Sprint(r2.Groups))
	add("names", joined(r1.Names), joined(r2.Names))
	add("exec-rc", r1.ExecRC, r2.ExecRC)
	add("matches", fmt.Sprint(r1.Matches), fmt.Sprint(r2.Matches))
	add("partial", fmt.Sprint(r1.Partial), fmt.Sprint(r2.Partial))
	add("match-err", r1.MatchErr, r2.MatchErr)
	add("panic", r1.Panic, r2.Panic)
	add("group-spans", joined(r1.GroupSpans), joined(r2.GroupSpans))
	add("extract", joined(r1.Extract), joined(r2.Extract))

	for _, name := range namedKeys(r1, r2) {
		add("named:"+name, r1.Named[name].String(), r2.Named[name].String())
	}

	add("find-index", r1.FindIndex, r2.FindIndex)
	add("find-str", r1.FindStr, r2.FindStr)
	add("find-all", joined(r1.FindAll), joined(r2.FindAll))
	add("replace-all", r1.ReplaceAll, r2.ReplaceAll)

	return ds
}

func namedKeys(r1, r2 *Record) []string {
	set := map[string]bool{}
	for k := range r1.Named {
		set[k] = true
	}
	for k := range r2.Named {
		set[k] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}

// diffParity compares the byte-API and string-API records of ONE side;
// they must agree in every normalized field. prefix is "v1" or "v2".
func diffParity(prefix string, bytesRec, strRec *Record) []Diff {
	var ds []Diff
	for _, d := range diffRecords(bytesRec, strRec) {
		ds = append(ds, Diff{
			Field: prefix + "-parity:" + d.Field,
			V1:    d.V1, // bytes-API value
			V2:    d.V2, // string-API value
		})
	}

	return ds
}
