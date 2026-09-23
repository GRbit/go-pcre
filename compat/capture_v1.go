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

// engineV1 is the v1 (PCRE 8.x) adapter of the engine seam.
type engineV1 struct{}

func (engineV1) compile(pattern string, cflags []string, jit bool) (compiled, error) {
	f := resolveFlags(cFlags1, cflags, "v1")
	var re pcre1.Regexp
	var err error
	if jit {
		re, err = pcre1.CompileJIT(pattern, f, jitStudy1)
	} else {
		re, err = pcre1.Compile(pattern, f)
	}

	return compiled1{re}, err
}

func (engineV1) execFlags(names []string) int { return resolveFlags(eFlags1, names, "v1") }

func (engineV1) compileErr(pattern string, err error) (int, string) {
	return parseV1CompileErr(pattern, err)
}

func (engineV1) rcName(rc int) string { return rcName1(rc) }

// v1's Matcher.Error carries no code; the raw Exec code names it.
func (engineV1) matchErr(_ error, rawRC int) string { return rcName1(rawRC) }

func (engineV1) namedErr(err error) string { return namedErr1(err) }

type compiled1 struct{ re pcre1.Regexp }

func (c compiled1) groups() int { return c.re.Groups() }

func (c compiled1) captureNames() []captureName {
	var out []captureName
	for _, cn := range c.re.CaptureNames() {
		out = append(out, captureName{Name: cn.Name, Index: cn.Index})
	}

	return out
}

// newMatcher returns an unbound Matcher, as the driver's Reset is the
// first observation and must be able to panic on its own.
func (c compiled1) newMatcher() matcher { return matcher1{re: c.re, m: new(pcre1.Matcher)} }

func (c compiled1) findIndex(subject []byte, ef int) []int   { return c.re.FindIndex(subject, ef) }
func (c compiled1) findString(subject string, ef int) string { return c.re.FindString(subject, ef) }
func (c compiled1) findAllIndex(subject []byte, ef int) [][]int {
	return c.re.FindAllIndex(subject, ef)
}
func (c compiled1) replaceAll(subject, repl []byte, ef int) []byte {
	return c.re.ReplaceAll(subject, repl, ef)
}
func (c compiled1) replaceAllString(subject, repl string, ef int) string {
	return c.re.ReplaceAllString(subject, repl, ef)
}

type matcher1 struct {
	re pcre1.Regexp
	m  *pcre1.Matcher
}

func (m matcher1) reset(subject []byte, ef int)          { m.m.Reset(m.re, subject, ef) }
func (m matcher1) resetString(subject string, ef int)    { m.m.ResetString(m.re, subject, ef) }
func (m matcher1) exec(subject []byte, ef int) int       { return m.m.Exec(subject, ef) }
func (m matcher1) execString(subject string, ef int) int { return m.m.ExecString(subject, ef) }
func (m matcher1) matches() bool                         { return m.m.Matches }
func (m matcher1) partial() bool                         { return m.m.Partial }
func (m matcher1) err() error                            { return m.m.Error }
func (m matcher1) groupIndices(g int) []int              { return m.m.GroupIndices(g) }
func (m matcher1) extract() [][]byte                     { return m.m.Extract() }
func (m matcher1) extractString() []string               { return m.m.ExtractString() }
func (m matcher1) named(name string) ([]byte, error)     { return m.m.Named(name) }
func (m matcher1) namedString(name string) (string, error) {
	return m.m.NamedString(name)
}
func (m matcher1) namedPresent(name string) bool { return m.m.NamedPresent(name) }
