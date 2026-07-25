package compat

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	pcre2 "github.com/GRbit/go-pcre/v2"
)

var cFlags2 = map[string]int{
	"ANCHORED":          pcre2.ANCHORED,
	"CASELESS":          pcre2.CASELESS,
	"DOLLAR_ENDONLY":    pcre2.DOLLAR_ENDONLY,
	"DOTALL":            pcre2.DOTALL,
	"DUPNAMES":          pcre2.DUPNAMES,
	"EXTENDED":          pcre2.EXTENDED,
	"EXTRA":             pcre2.EXTRA,
	"FIRSTLINE":         pcre2.FIRSTLINE,
	"JAVASCRIPT_COMPAT": pcre2.JAVASCRIPT_COMPAT,
	"MULTILINE":         pcre2.MULTILINE,
	"NO_AUTO_CAPTURE":   pcre2.NO_AUTO_CAPTURE,
	"UNGREEDY":          pcre2.UNGREEDY,
	"UTF":               pcre2.UTF,
	"UCP":               pcre2.UCP,
	"NO_UTF_CHECK":      pcre2.NO_UTF_CHECK,
}

// NO_START_OPTIMIZE maps to the v2 compile constant even in the exec map:
// v1 accepted it at match time, and the suite passes it through to
// pcre2_match on purpose to pin down what a migrated call site would see.
var eFlags2 = map[string]int{
	"ANCHORED":          pcre2.ANCHORED,
	"NOTBOL":            pcre2.NOTBOL,
	"NOTEOL":            pcre2.NOTEOL,
	"NOTEMPTY":          pcre2.NOTEMPTY,
	"NOTEMPTY_ATSTART":  pcre2.NOTEMPTY_ATSTART,
	"NO_START_OPTIMIZE": pcre2.NO_START_OPTIMIZE,
	"PARTIAL_SOFT":      pcre2.PARTIAL_SOFT,
	"PARTIAL_HARD":      pcre2.PARTIAL_HARD,
}

const jitStudy2 = pcre2.JIT_COMPLETE | pcre2.JIT_PARTIAL_SOFT | pcre2.JIT_PARTIAL_HARD

func rcName2(rc int) string {
	if rc >= 0 {
		return fmt.Sprintf("OK(%d)", rc)
	}
	// PCRE2 reports invalid UTF in the subject as one code per problem
	// (UTF8_ERR1..21 and the 16/32-bit families, -3..-28). v1 had the
	// single ERROR_BADUTF8; normalize the whole family to match it.
	if rc >= -28 && rc <= -3 {
		return "BADUTF"
	}
	switch rc {
	case pcre2.ERROR_NOMATCH:
		return "NOMATCH"
	case pcre2.ERROR_PARTIAL:
		return "PARTIAL"
	case pcre2.ERROR_MATCHLIMIT:
		return "MATCHLIMIT"
	case pcre2.ERROR_DEPTHLIMIT:
		return "DEPTHLIMIT"
	case pcre2.ERROR_HEAPLIMIT:
		return "HEAPLIMIT"
	case pcre2.ERROR_BADUTFOFFSET:
		return "BADUTFOFFSET"
	case pcre2.ERROR_JIT_STACKLIMIT:
		return "JIT_STACKLIMIT"
	case pcre2.ERROR_BADOPTION:
		return "BADOPTION"
	case pcre2.ERROR_JIT_BADOPTION:
		return "JIT_BADOPTION"
	case pcre2.ERROR_NOMEMORY:
		return "NOMEMORY"
	case pcre2.ERROR_NULL:
		return "NULL"
	case pcre2.ERROR_BADMAGIC:
		return "BADMAGIC"
	case pcre2.ERROR_NOSUBSTRING:
		return "NOSUBSTRING"
	case pcre2.ERROR_NOUNIQUESUBSTRING:
		return "NOUNIQUESUBSTRING"
	case pcre2.ERROR_CALLOUT:
		return "CALLOUT"
	case pcre2.ERROR_BADDATA:
		return "BADDATA"
	case pcre2.ERROR_BADOFFSET:
		return "BADOFFSET"
	case pcre2.ERROR_INTERNAL:
		return "INTERNAL"
	case pcre2.ERROR_UNAVAILABLE:
		return "UNAVAILABLE"
	case pcre2.ERROR_UNSET:
		return "UNSET"
	default:
		return fmt.Sprintf("ERR(%d)", rc)
	}
}

func namedErr2(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, pcre2.ErrNonUniqueName):
		return "NONUNIQUE"
	case strings.Contains(err.Error(), "unknown name"):
		return "UNKNOWN"
	default:
		return "OTHER:" + err.Error()
	}
}

func captureV2(c Case, ax Axis) *Record {
	r := &Record{CompileOffset: -1}

	var re pcre2.Regexp
	var cerr error
	if p := guard(func() {
		if ax.JIT {
			re, cerr = pcre2.CompileJIT(c.Pattern, resolveFlags(cFlags2, c.CFlags, "v2"), jitStudy2)
		} else {
			re, cerr = pcre2.Compile(c.Pattern, resolveFlags(cFlags2, c.CFlags, "v2"))
		}
	}); p != "" {
		r.CompileMsg = p

		return r
	}
	if cerr != nil {
		var ce *pcre2.CompileError
		if errors.As(cerr, &ce) {
			r.CompileOffset, r.CompileMsg = ce.Offset, ce.Message
		} else {
			r.CompileMsg = cerr.Error()
		}

		return r
	}
	r.CompileOK = true

	r.Groups = re.Groups()
	names := map[string]bool{}
	for _, cn := range re.CaptureNames() {
		r.Names = append(r.Names, fmt.Sprintf("%s=%d", cn.Name, cn.Index))
		names[cn.Name] = true
	}

	ef := resolveFlags(eFlags2, ax.EFlags, "v2")
	m := new(pcre2.Matcher)
	r.Panic = guard(func() {
		if ax.Str {
			m.ResetString(re, c.Subject, ef)
		} else {
			m.Reset(re, []byte(c.Subject), ef)
		}
	})

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
		r.ExecRC = rcName2(rawRC)
	}

	r.Matches, r.Partial = m.Matches, m.Partial
	if m.Error != nil {
		var me *pcre2.MatchError
		if errors.As(m.Error, &me) {
			r.MatchErr = rcName2(me.Code)
		} else {
			r.MatchErr = "OTHER:" + m.Error.Error()
		}
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
					nr.Err = namedErr2(err)
				} else {
					v, err := m.Named(name)
					nr.Val = strconv.Quote(string(v))
					nr.Err = namedErr2(err)
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
