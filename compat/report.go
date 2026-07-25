package compat

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	pcre1 "github.com/GRbit/go-pcre"
	pcre2 "github.com/GRbit/go-pcre/v2"
)

// taggedDiff is a Diff plus its classification ("" = unexplained).
type taggedDiff struct {
	Diff
	Tag string
}

// result is the outcome of one (case, axis) comparison.
type result struct {
	c     Case
	axis  string
	diffs []taggedDiff
}

var collector struct {
	sync.Mutex
	results []result
}

func collect(c Case, axis string, diffs []taggedDiff) {
	collector.Lock()
	defer collector.Unlock()
	collector.results = append(collector.results, result{c: c, axis: axis, diffs: diffs})
}

// writeReport renders report.md from everything collected during the run.
func writeReport(path string) error {
	collector.Lock()
	defer collector.Unlock()
	rs := collector.results
	if countCases(rs) != len(allCases()) {
		return nil // partial run (-run filter): keep the committed full report
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].c.ID != rs[j].c.ID {
			return rs[i].c.ID < rs[j].c.ID
		}

		return rs[i].axis < rs[j].axis
	})

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	comparisons := len(rs)
	var unexplained, known []result
	knownCounts := map[string]int{}
	knownExample := map[string]result{}
	for _, r := range rs {
		hasUnexplained, hasKnown := false, false
		for _, d := range r.diffs {
			if d.Tag == "" {
				hasUnexplained = true

				continue
			}
			hasKnown = true
			knownCounts[d.Tag]++
			if _, ok := knownExample[d.Tag]; !ok {
				knownExample[d.Tag] = r
			}
		}
		if hasUnexplained {
			unexplained = append(unexplained, r)
		}
		if hasKnown {
			known = append(known, r)
		}
	}

	w("# v1 vs v2 differential report\n\n")
	w("Cases: %d, comparisons (case x axis): %d, runs with known diffs: %d, runs with UNEXPLAINED diffs: %d\n\n",
		countCases(rs), comparisons, len(known), len(unexplained))

	w("## Unexplained differences\n\n")
	if len(unexplained) == 0 {
		w("None.\n\n")
	}
	for _, r := range unexplained {
		w("### %s [%s]\n\n", r.c.ID, r.axis)
		w("- pattern: `%q`\n- subject: `%q`\n- cflags: %v, eflags in axis\n",
			r.c.Pattern, r.c.Subject, r.c.CFlags)
		w("- repro: `go test -run 'TestDiff/%s'`\n\n", r.c.ID)
		w("| field | v1 | v2 |\n|---|---|---|\n")
		for _, d := range r.diffs {
			if d.Tag == "" {
				w("| %s | `%s` | `%s` |\n", d.Field, d.V1, d.V2)
			}
		}
		w("\n")
	}

	w("## Known divergences observed\n\n")
	tags := make([]string, 0, len(knownCounts))
	for t := range knownCounts {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	if len(tags) == 0 {
		w("None.\n\n")
	}
	for _, t := range tags {
		ex := knownExample[t]
		w("- **%s**: %d diff(s); example: %s [%s]\n", t, knownCounts[t], ex.c.ID, ex.axis)
	}
	w("\n")

	w("## Library configuration\n\n")
	w("### v1 (PCRE 8.x)\n\n```\n%s```\n\n", pcre1.ConfigAll())
	w("### v2 (PCRE2, version %s)\n\n```\n%s```\n",
		pcre2.Config(pcre2.CONFIG_VERSION), pcre2.ConfigAll())

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func countCases(rs []result) int {
	ids := map[string]bool{}
	for _, r := range rs {
		ids[r.c.ID] = true
	}

	return len(ids)
}
