package pcre

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// ReplaceAll returns a copy of subject with pattern matches replaced by
// repl (literally: no $-template expansion; see ReplaceAllTemplate for
// that). The iteration follows the canonical global-match protocol, whose
// output is Perl s///g-verified byte for byte (TestReplaceAll).
// A match whose start \K moved backwards (possible only on libpcre2 <
// 10.38) ends the replacement; the rest of the subject is copied as is.
func (re Regexp) ReplaceAll(subject, repl []byte, flags int) []byte {
	m := re.matcherFromPool()
	defer re.putMatcher(m)

	r := make([]byte, 0, len(subject))
	prev := 0
	re.iterate(m, subject, flags, func(start, end int) bool {
		r = append(append(r, subject[prev:start]...), repl...)
		prev = end

		return true
	})

	return append(r, subject[prev:]...)
}

// ReplaceAllString is same as ReplaceAll, but accept strings as arguments.
// It delegates to ReplaceAll: converting the subject once is far cheaper
// than re-converting the remainder on every iteration.
func (re Regexp) ReplaceAllString(subj, repl string, flags int) string {
	return string(re.ReplaceAll([]byte(subj), []byte(repl), flags))
}

// ReplaceAllTemplate returns a copy of subject with all pattern matches
// replaced through pcre2_substitute, so template may reference capture
// groups as $1, ${name} or $<name> ($$ is a literal $). Unset groups
// substitute as empty. flags may add match options and SUBSTITUTE_*
// extras (e.g. SUBSTITUTE_EXTENDED for \U and ${n:-default} forms).
// This API is new in v2; v1 had no template replacement.
func (re Regexp) ReplaceAllTemplate(subject, template []byte, flags int) ([]byte, error) {
	return re.substituteAll(subject, template, flags)
}

// ReplaceAllTemplateString is same as ReplaceAllTemplate, but accepts and
// returns strings.
func (re Regexp) ReplaceAllTemplateString(subject, template string, flags int) (string, error) {
	out, err := re.substituteAll([]byte(subject), []byte(template), flags)

	return string(out), err
}

// substituteAll wraps pcre2_substitute with PCRE2_SUBSTITUTE_GLOBAL and
// the OVERFLOW_LENGTH buffer protocol: when the first attempt reports
// NOMEMORY, the needed size comes back in outLen and one retry suffices
// (pcre2_substitute.3). UNSET_EMPTY makes unset groups substitute as empty
// rather than erroring, matching Go template expectations.
func (re Regexp) substituteAll(subject, template []byte, flags int) ([]byte, error) {
	opts := C.uint32_t(flags) |
		C.PCRE2_SUBSTITUTE_GLOBAL |
		C.PCRE2_SUBSTITUTE_OVERFLOW_LENGTH |
		C.PCRE2_SUBSTITUTE_UNSET_EMPTY

	buf := make([]byte, len(subject)+len(template)+64)
	for attempt := 0; ; attempt++ {
		outLen := C.PCRE2_SIZE(len(buf))
		rc := C.pcre2_substitute(re.code.ptr(),
			cptr(subject), C.PCRE2_SIZE(len(subject)), 0,
			opts, nil, nil,
			cptr(template), C.PCRE2_SIZE(len(template)),
			(*C.PCRE2_UCHAR)(unsafe.Pointer(&buf[0])), &outLen)
		runtime.KeepAlive(re.code)

		if rc == C.PCRE2_ERROR_NOMEMORY && attempt == 0 {
			buf = make([]byte, outLen) // required size, incl. trailing NUL

			continue
		}
		if rc < 0 {
			return nil, fmt.Errorf("pcre2_substitute (%d): %s", int(rc), errorMessage(rc))
		}

		return buf[:outLen], nil
	}
}
