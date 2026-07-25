package compat

import (
	"fmt"
	"strconv"
	"strings"

	pcre1 "github.com/GRbit/go-pcre"
)

// Symbolic flag names use v2's canonical spelling; this file maps them to
// the v1 constants. The two maps must stay aligned with capture_v2.go.
var cFlags1 = map[string]int{
	"ANCHORED":          pcre1.ANCHORED,
	"CASELESS":          pcre1.CASELESS,
	"DOLLAR_ENDONLY":    pcre1.DOLLAR_ENDONLY,
	"DOTALL":            pcre1.DOTALL,
	"DUPNAMES":          pcre1.DUPNAMES,
	"EXTENDED":          pcre1.EXTENDED,
	"EXTRA":             pcre1.EXTRA,
	"FIRSTLINE":         pcre1.FIRSTLINE,
	"JAVASCRIPT_COMPAT": pcre1.JAVASCRIPT_COMPAT,
	"MULTILINE":         pcre1.MULTILINE,
	"NO_AUTO_CAPTURE":   pcre1.NO_AUTO_CAPTURE,
	"UNGREEDY":          pcre1.UNGREEDY,
	"UTF":               pcre1.UTF8,
	"UCP":               pcre1.UCP,
	"NO_UTF_CHECK":      pcre1.NO_UTF8_CHECK,
}

var eFlags1 = map[string]int{
	"ANCHORED":          pcre1.ANCHORED,
	"NOTBOL":            pcre1.NOTBOL,
	"NOTEOL":            pcre1.NOTEOL,
	"NOTEMPTY":          pcre1.NOTEMPTY,
	"NOTEMPTY_ATSTART":  pcre1.NOTEMPTY_ATSTART,
	"NO_START_OPTIMIZE": pcre1.NO_START_OPTIMIZE,
	"PARTIAL_SOFT":      pcre1.PARTIAL_SOFT,
	"PARTIAL_HARD":      pcre1.PARTIAL_HARD,
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

// jitStudy1 requests JIT for complete and both partial modes, so every
// exec-flag variant of a case runs JIT-compiled on the JIT axis.
const jitStudy1 = pcre1.STUDY_JIT_COMPILE |
	pcre1.STUDY_JIT_PARTIAL_SOFT_COMPILE |
	pcre1.STUDY_JIT_PARTIAL_HARD_COMPILE

// parseV1CompileErr splits v1's "pattern (offset): message" rendering.
func parseV1CompileErr(pattern string, err error) (int, string) {
	s := err.Error()
	prefix := pattern + " ("
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return -1, s
	}
	i := strings.Index(rest, "): ")
	if i < 0 {
		return -1, s
	}
	off, aerr := strconv.Atoi(rest[:i])
	if aerr != nil {
		return -1, s
	}

	return off, rest[i+3:]
}

func rcName1(rc int) string {
	if rc >= 0 {
		return fmt.Sprintf("OK(%d)", rc)
	}
	switch rc {
	case pcre1.ERROR_NOMATCH:
		return "NOMATCH"
	case pcre1.ERROR_PARTIAL:
		return "PARTIAL"
	case pcre1.ERROR_MATCHLIMIT:
		return "MATCHLIMIT"
	case pcre1.ERROR_RECURSIONLIMIT:
		return "DEPTHLIMIT" // PCRE2's name for the same limit
	case pcre1.ERROR_BADUTF8:
		return "BADUTF" // PCRE2 splits this into per-problem codes
	case pcre1.ERROR_BADUTF8_OFFSET:
		return "BADUTFOFFSET"
	case pcre1.ERROR_JIT_STACKLIMIT:
		return "JIT_STACKLIMIT"
	case pcre1.ERROR_BADOPTION:
		return "BADOPTION"
	case pcre1.ERROR_NOMEMORY:
		return "NOMEMORY"
	case pcre1.ERROR_NULL:
		return "NULL"
	case pcre1.ERROR_BADMAGIC:
		return "BADMAGIC"
	case pcre1.ERROR_NOSUBSTRING:
		return "NOSUBSTRING"
	case pcre1.ERROR_CALLOUT:
		return "CALLOUT"
	case pcre1.ERROR_BADPARTIAL:
		return "BADPARTIAL"
	case pcre1.ERROR_INTERNAL:
		return "INTERNAL"
	case pcre1.ERROR_BADCOUNT:
		return "BADCOUNT"
	case pcre1.ERROR_UNKNOWN_OPCODE:
		return "UNKNOWN_OPCODE"
	default:
		return fmt.Sprintf("ERR(%d)", rc)
	}
}

func namedErr1(err error) string {
	switch {
	case err == nil:
		return ""
	case strings.Contains(err.Error(), "unknown name"):
		return "UNKNOWN"
	default:
		return "OTHER:" + err.Error()
	}
}

func captureV1(c Case, ax Axis) *Record {
	r := &Record{CompileOffset: -1}

	var re pcre1.Regexp
	var cerr error
	if p := guard(func() {
		if ax.JIT {
			re, cerr = pcre1.CompileJIT(c.Pattern, resolveFlags(cFlags1, c.CFlags, "v1"), jitStudy1)
		} else {
			re, cerr = pcre1.Compile(c.Pattern, resolveFlags(cFlags1, c.CFlags, "v1"))
		}
	}); p != "" {
		r.CompileMsg = p

		return r
	}
	if cerr != nil {
		r.CompileOffset, r.CompileMsg = parseV1CompileErr(c.Pattern, cerr)

		return r
	}
	r.CompileOK = true

	r.Groups = re.Groups()
	names := map[string]bool{}
	for _, cn := range re.CaptureNames() {
		r.Names = append(r.Names, fmt.Sprintf("%s=%d", cn.Name, cn.Index))
		names[cn.Name] = true
	}

	ef := resolveFlags(eFlags1, ax.EFlags, "v1")
	m := new(pcre1.Matcher)
	r.Panic = guard(func() {
		if ax.Str {
			m.ResetString(re, c.Subject, ef)
		} else {
			m.Reset(re, []byte(c.Subject), ef)
		}
	})

	// Raw return code, re-run through Exec: it bypasses v1's checkMatch,
	// which panics on several codes (D1), so this works even when the
	// Reset above panicked (the Matcher is initialized before matching).
	rawRC := 0
	if p := guard(func() {
		if ax.Str {
			rawRC = m.ExecString(c.Subject, ef)
		} else {
			rawRC = m.Exec([]byte(c.Subject), ef)
		}
	}); p != "" {
		r.ExecRC = p
	} else {
		r.ExecRC = rcName1(rawRC)
	}

	r.Matches, r.Partial = m.Matches, m.Partial
	if m.Error != nil {
		r.MatchErr = rcName1(rawRC)
	}

	if m.Matches {
		for g := 0; g <= r.Groups; g++ {
			if gi := m.GroupIndices(g); gi == nil {
				r.GroupSpans = append(r.GroupSpans, "unset")
			} else {
				r.GroupSpans = append(r.GroupSpans, span(gi[0], gi[1]))
			}
		}
		if ax.Str {
			for _, s := range m.ExtractString() {
				r.Extract = append(r.Extract, strconv.Quote(s))
			}
		} else {
			for _, b := range m.Extract() {
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
					v, err := m.NamedString(name)
					nr.Val = strconv.Quote(v)
					nr.Err = namedErr1(err)
				} else {
					v, err := m.Named(name)
					nr.Val = strconv.Quote(string(v))
					nr.Err = namedErr1(err)
				}
				nr.Present = m.NamedPresent(name)
			}); p != "" {
				nr.Err = p
			}
			r.Named[name] = nr
		}
	}

	if p := guard(func() {
		if fi := re.FindIndex([]byte(c.Subject), ef); fi != nil {
			r.FindIndex = span(fi[0], fi[1])
		}
		r.FindStr = strconv.Quote(re.FindString(c.Subject, ef))
		r.FindAll = spansOf(re.FindAllIndex([]byte(c.Subject), ef))
	}); p != "" {
		r.FindIndex = p
	}

	if p := guard(func() {
		if ax.Str {
			r.ReplaceAll = strconv.Quote(re.ReplaceAllString(c.Subject, c.replacement(), ef))
		} else {
			r.ReplaceAll = strconv.Quote(string(re.ReplaceAll([]byte(c.Subject), []byte(c.replacement()), ef)))
		}
	}); p != "" {
		r.ReplaceAll = p
	}

	return r
}
