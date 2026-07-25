// Package compat is a differential test suite: it runs one corpus of
// regex cases through go-pcre v1 (PCRE 8.x) and v2 (PCRE2) and compares
// every observable output. See README.md.
package compat

import (
	"fmt"
	"strings"
)

// Case is one corpus entry, run through both libraries on several axes.
type Case struct {
	ID      string
	Pattern string
	Subject string

	// CFlags are symbolic compile flags ("CASELESS", "UTF", ...), mapped
	// to each library's own constants; see capture_v1.go / capture_v2.go.
	CFlags []string

	// EFlags lists exec-flag variants to run. nil means one variant with
	// no flags. Each variant multiplies the axis fan-out.
	EFlags [][]string

	// Repl is the ReplaceAll replacement text; empty means "<>".
	Repl string

	// Known lists the divergence tags (D-numbers from MIGRATION.md, or
	// "DIALECT:<slug>" for engine dialect changes) that explain the
	// differences this case is expected to show. A case with Known set
	// must diff on at least one axis; a case without Known must not diff
	// at all beyond the global classification rules.
	Known []string

	// NoJIT skips the JIT axis, for cases where JIT compilation itself
	// is the thing under test elsewhere or is meaningless.
	NoJIT bool
}

func (c Case) replacement() string {
	if c.Repl == "" {
		return "<>"
	}

	return c.Repl
}

// Axis is one way a case is run: interpreter or JIT, []byte or string
// API, one exec-flag variant.
type Axis struct {
	JIT    bool
	Str    bool
	EFlags []string
}

func (a Axis) String() string {
	s := "plain"
	if a.JIT {
		s = "jit"
	}
	if a.Str {
		s += "-str"
	} else {
		s += "-bytes"
	}
	if len(a.EFlags) > 0 {
		s += "+" + strings.Join(a.EFlags, ",")
	}

	return s
}

// axes expands a case into its full axis fan-out.
func axes(c Case) []Axis {
	variants := c.EFlags
	if variants == nil {
		variants = [][]string{nil}
	}

	var out []Axis
	for _, jit := range []bool{false, true} {
		if jit && c.NoJIT {
			continue
		}
		for _, str := range []bool{false, true} {
			for _, ev := range variants {
				out = append(out, Axis{JIT: jit, Str: str, EFlags: ev})
			}
		}
	}

	return out
}

// NamedResult is the outcome of Named/NamedPresent for one group name.
type NamedResult struct {
	Val     string // %q of the captured value
	Err     string // "", "UNKNOWN", "NONUNIQUE", or "PANIC:..."
	Present bool
}

func (n NamedResult) String() string {
	return fmt.Sprintf("val=%s err=%s present=%v", n.Val, n.Err, n.Present)
}

// Record is everything observable from running one (case, axis) pair on
// one side. All fields are normalized (symbolic error names, quoted
// strings) so that equality means behavioral equality.
type Record struct {
	CompileOK     bool
	CompileOffset int    // error offset; -1 when CompileOK or unparsable
	CompileMsg    string // report-only: never diffed, wording differs (D3)

	Groups int
	Names  []string // "name=index" in CaptureNames order

	ExecRC   string // symbolic raw Exec return code
	Matches  bool
	Partial  bool
	MatchErr string // symbolic Matcher.Error after MatchWFlags; "" if none
	Panic    string // panic text from the match call; "" if none

	GroupSpans []string // group 0..Groups: "start:end" or "unset"
	Extract    []string // %q per entry; nil when no match
	Named      map[string]NamedResult

	FindIndex  string // "start:end" or ""
	FindStr    string // %q of FindString's result
	FindAll    []string
	ReplaceAll string // %q of the result, or "PANIC:..."
}

func span(start, end int) string { return fmt.Sprintf("%d:%d", start, end) }

func spansOf(pairs [][]int) []string {
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, span(p[0], p[1]))
	}

	return out
}

// guard runs f and converts a panic into a recorded string.
func guard(f func()) (panicked string) {
	defer func() {
		if p := recover(); p != nil {
			panicked = fmt.Sprintf("PANIC:%v", p)
		}
	}()
	f()

	return ""
}
