package compat

import (
	"fmt"
	"strconv"
)

// engine is the seam between the differential driver (capture) and one
// go-pcre major version. Each method delegates to the same-named API of
// that version; the driver never sees a version-specific type, so the
// observation sequence exists once and a harness bug cannot masquerade as
// a library difference. Only what the versions genuinely disagree on is
// left to the adapters: flag constants, error code names, compile-error
// extraction and named-lookup error classification.
type engine interface {
	compile(pattern string, cflags []string, jit bool) (compiled, error)
	execFlags(names []string) int

	// compileErr splits a compile error into its offset (-1 if unknown)
	// and message.
	compileErr(pattern string, err error) (int, string)
	rcName(rc int) string
	// matchErr renders Matcher.Error; rawRC is the raw Exec code of the
	// same match for versions whose error carries no code of its own.
	matchErr(err error, rawRC int) string
	namedErr(err error) string
}

type captureName struct {
	Name  string
	Index int
}

type compiled interface {
	groups() int
	captureNames() []captureName
	newMatcher() matcher
	findIndex(subject []byte, eflags int) []int
	findString(subject string, eflags int) string
	findAllIndex(subject []byte, eflags int) [][]int
	replaceAll(subject, repl []byte, eflags int) []byte
	replaceAllString(subject, repl string, eflags int) string
}

type matcher interface {
	reset(subject []byte, eflags int)
	resetString(subject string, eflags int)
	exec(subject []byte, eflags int) int
	execString(subject string, eflags int) int
	matches() bool
	partial() bool
	err() error
	groupIndices(group int) []int
	extract() [][]byte
	extractString() []string
	named(name string) ([]byte, error)
	namedString(name string) (string, error)
	namedPresent(name string) bool
}

func resolveFlags(m map[string]int, names []string, side string) int {
	f := 0
	for _, n := range names {
		v, ok := m[n]
		if !ok {
			panic("compat: flag " + n + " has no " + side + " mapping")
		}
		f |= v
	}

	return f
}

// capture runs one (case, axis) pair through e and records everything
// observable. Every library call is guarded: a panic is recorded in the
// field it interrupted, and the run continues with the next observation.
func capture(e engine, c Case, ax Axis) *Record {
	r := &Record{CompileOffset: -1}

	var re compiled
	var cerr error
	if p := guard(func() { re, cerr = e.compile(c.Pattern, c.CFlags, ax.JIT) }); p != "" {
		r.CompileMsg = p

		return r
	}
	if cerr != nil {
		r.CompileOffset, r.CompileMsg = e.compileErr(c.Pattern, cerr)

		return r
	}
	r.CompileOK = true

	r.Groups = re.groups()
	names := map[string]bool{}
	for _, cn := range re.captureNames() {
		r.Names = append(r.Names, fmt.Sprintf("%s=%d", cn.Name, cn.Index))
		names[cn.Name] = true
	}

	ef := e.execFlags(ax.EFlags)
	m := re.newMatcher()
	r.Panic = guard(func() {
		if ax.Str {
			m.resetString(c.Subject, ef)
		} else {
			m.reset([]byte(c.Subject), ef)
		}
	})

	// Raw return code, re-run through Exec: it bypasses v1's checkMatch,
	// which panics on several codes (D1), so this works even when the
	// Reset above panicked (the Matcher is initialized before matching).
	rawRC := 0
	if p := guard(func() {
		if ax.Str {
			rawRC = m.execString(c.Subject, ef)
		} else {
			rawRC = m.exec([]byte(c.Subject), ef)
		}
	}); p != "" {
		r.ExecRC = p
	} else {
		r.ExecRC = e.rcName(rawRC)
	}

	r.Matches, r.Partial = m.matches(), m.partial()
	if err := m.err(); err != nil {
		r.MatchErr = e.matchErr(err, rawRC)
	}

	if m.matches() {
		for g := 0; g <= r.Groups; g++ {
			if gi := m.groupIndices(g); gi == nil {
				r.GroupSpans = append(r.GroupSpans, "unset")
			} else {
				r.GroupSpans = append(r.GroupSpans, span(gi[0], gi[1]))
			}
		}
		if ax.Str {
			for _, s := range m.extractString() {
				r.Extract = append(r.Extract, strconv.Quote(s))
			}
		} else {
			for _, b := range m.extract() {
				r.Extract = append(r.Extract, strconv.Quote(string(b)))
			}
		}
	}

	if len(names) > 0 {
		r.Named = map[string]NamedResult{}
		for name := range names {
			var nr NamedResult
			if p := guard(func() {
				if ax.Str {
					v, err := m.namedString(name)
					nr.Val = strconv.Quote(v)
					nr.Err = e.namedErr(err)
				} else {
					v, err := m.named(name)
					nr.Val = strconv.Quote(string(v))
					nr.Err = e.namedErr(err)
				}
				nr.Present = m.namedPresent(name)
			}); p != "" {
				nr.Err = p
			}
			r.Named[name] = nr
		}
	}

	if p := guard(func() {
		if fi := re.findIndex([]byte(c.Subject), ef); fi != nil {
			r.FindIndex = span(fi[0], fi[1])
		}
		r.FindStr = strconv.Quote(re.findString(c.Subject, ef))
		r.FindAll = spansOf(re.findAllIndex([]byte(c.Subject), ef))
	}); p != "" {
		r.FindIndex = p
	}

	if p := guard(func() {
		if ax.Str {
			r.ReplaceAll = strconv.Quote(re.replaceAllString(c.Subject, c.replacement(), ef))
		} else {
			r.ReplaceAll = strconv.Quote(string(re.replaceAll([]byte(c.Subject), []byte(c.replacement()), ef)))
		}
	}); p != "" {
		r.ReplaceAll = p
	}

	return r
}
