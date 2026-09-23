package compat

import (
	"errors"
	"fmt"
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

// engineV2 is the v2 (PCRE2) adapter of the engine seam.
type engineV2 struct{}

func (engineV2) compile(pattern string, cflags []string, jit bool) (compiled, error) {
	f := resolveFlags(cFlags2, cflags, "v2")
	var re pcre2.Regexp
	var err error
	if jit {
		re, err = pcre2.CompileJIT(pattern, f, jitStudy2)
	} else {
		re, err = pcre2.Compile(pattern, f)
	}

	return compiled2{re}, err
}

func (engineV2) execFlags(names []string) int { return resolveFlags(eFlags2, names, "v2") }

func (engineV2) compileErr(_ string, err error) (int, string) {
	var ce *pcre2.CompileError
	if errors.As(err, &ce) {
		return ce.Offset, ce.Message
	}

	return -1, err.Error()
}

func (engineV2) rcName(rc int) string { return rcName2(rc) }

func (engineV2) matchErr(err error, _ int) string {
	var me *pcre2.MatchError
	if errors.As(err, &me) {
		return rcName2(me.Code)
	}

	return "OTHER:" + err.Error()
}

func (engineV2) namedErr(err error) string { return namedErr2(err) }

type compiled2 struct{ re pcre2.Regexp }

func (c compiled2) groups() int { return c.re.Groups() }

func (c compiled2) captureNames() []captureName {
	var out []captureName
	for _, cn := range c.re.CaptureNames() {
		out = append(out, captureName{Name: cn.Name, Index: cn.Index})
	}

	return out
}

func (c compiled2) newMatcher() matcher { return matcher2{re: c.re, m: new(pcre2.Matcher)} }

func (c compiled2) findIndex(subject []byte, ef int) []int   { return c.re.FindIndex(subject, ef) }
func (c compiled2) findString(subject string, ef int) string { return c.re.FindString(subject, ef) }
func (c compiled2) findAllIndex(subject []byte, ef int) [][]int {
	return c.re.FindAllIndex(subject, ef)
}
func (c compiled2) replaceAll(subject, repl []byte, ef int) []byte {
	return c.re.ReplaceAll(subject, repl, ef)
}
func (c compiled2) replaceAllString(subject, repl string, ef int) string {
	return c.re.ReplaceAllString(subject, repl, ef)
}

type matcher2 struct {
	re pcre2.Regexp
	m  *pcre2.Matcher
}

func (m matcher2) reset(subject []byte, ef int)          { m.m.Reset(m.re, subject, ef) }
func (m matcher2) resetString(subject string, ef int)    { m.m.ResetString(m.re, subject, ef) }
func (m matcher2) exec(subject []byte, ef int) int       { return m.m.Exec(subject, ef) }
func (m matcher2) execString(subject string, ef int) int { return m.m.ExecString(subject, ef) }
func (m matcher2) matches() bool                         { return m.m.Matches }
func (m matcher2) partial() bool                         { return m.m.Partial }
func (m matcher2) err() error                            { return m.m.Error }
func (m matcher2) groupIndices(g int) []int              { return m.m.GroupIndices(g) }
func (m matcher2) extract() [][]byte                     { return m.m.Extract() }
func (m matcher2) extractString() []string               { return m.m.ExtractString() }
func (m matcher2) named(name string) ([]byte, error)     { return m.m.Named(name) }
func (m matcher2) namedString(name string) (string, error) {
	return m.m.NamedString(name)
}
func (m matcher2) namedPresent(name string) bool { return m.m.NamedPresent(name) }
