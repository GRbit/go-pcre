package compat

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	if err := writeReport("report.md"); err != nil {
		fmt.Fprintf(os.Stderr, "compat: writing report.md: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// TestDiff runs every corpus case through both libraries on every axis
// and fails on any unexplained difference, and on any case whose Known
// annotation stops reproducing.
func TestDiff(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range allCases() {
		if seen[c.ID] {
			t.Fatalf("duplicate case ID %q", c.ID)
		}
		seen[c.ID] = true

		t.Run(c.ID, func(t *testing.T) {
			runCase(t, c)
		})
	}
}

func runCase(t *testing.T, c Case) {
	t.Helper()

	knownFired := false
	// Per (jit, eflags) variant, keep the byte-API records of both sides
	// for the string-vs-bytes parity check.
	type sideRecs struct{ r1, r2 *Record }
	bytesRecs := map[string]sideRecs{}

	for _, ax := range axes(c) {
		r1 := capture(engineV1{}, c, ax)
		r2 := capture(engineV2{}, c, ax)

		diffs := diffRecords(r1, r2)

		variantKey := fmt.Sprintf("jit=%v eflags=%v", ax.JIT, ax.EFlags)
		if !ax.Str {
			bytesRecs[variantKey] = sideRecs{r1: r1, r2: r2}
		} else if base, ok := bytesRecs[variantKey]; ok {
			diffs = append(diffs, diffParity("v1", base.r1, r1)...)
			diffs = append(diffs, diffParity("v2", base.r2, r2)...)
		}

		tagged := make([]taggedDiff, 0, len(diffs))
		for _, d := range diffs {
			tag := classify(c, r1, r2, d)
			if tag != "" {
				knownFired = true
			} else {
				t.Errorf("[%s] UNEXPLAINED diff in %s:\n  v1: %s\n  v2: %s",
					ax, d.Field, d.V1, d.V2)
			}
			tagged = append(tagged, taggedDiff{Diff: d, Tag: tag})
		}
		collect(c, ax.String(), tagged)
	}

	if len(c.Known) > 0 && !knownFired {
		t.Errorf("case is annotated Known=%v but v1 and v2 agreed on every axis; "+
			"either the divergence no longer reproduces or the annotation is wrong", c.Known)
	}
}
