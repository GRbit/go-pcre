package pcre

/*
#cgo pkg-config: libpcre2-8
#cgo noescape pcre2_pattern_info
#cgo nocallback pcre2_pattern_info
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// pcre2_pattern_info writes its answer through a pointer whose C type
// depends on the key: uint32_t for almost everything, size_t for the two
// size keys, a pointer for the name table and the first-code-unit bitmap.
// Using the wrong width smashes the stack, so the width is decided here,
// once, by key. The noescape and nocallback directives above (cgo needs
// both) keep the output variable on the Go stack: pcre2_pattern_info only
// writes through it during the call and never calls back into Go.

// info32 queries a uint32_t-valued key.
func info32(p *C.pcre2_code, key C.uint32_t) C.uint32_t {
	var v C.uint32_t
	C.pcre2_pattern_info(p, key, unsafe.Pointer(&v))

	return v
}

// infoSize queries a size_t-valued key (INFO_SIZE, INFO_JITSIZE).
func infoSize(p *C.pcre2_code, key C.uint32_t) C.size_t {
	var v C.size_t
	C.pcre2_pattern_info(p, key, unsafe.Pointer(&v))

	return v
}

// Info returns a numeric fact about the compiled pattern for one of the
// INFO_* keys (pcre2_pattern_info), for example INFO_MINLENGTH or
// INFO_MAXLOOKBEHIND. size_t-valued keys (INFO_SIZE, INFO_JITSIZE) and
// uint32-valued keys are both returned as uint64. Keys whose answer is a
// pointer (INFO_NAMETABLE, INFO_FIRSTBITMAP) and keys this package does not
// know return an error: the output width of an unknown key cannot be
// guessed safely. Groups, CaptureNames and JITCompiled are the typed
// front ends for the keys they cover. New in v2.
// C docs: https://www.pcre.org/current/doc/html/pcre2_pattern_info.html
func (re Regexp) Info(key int) (uint64, error) {
	switch key {
	case INFO_SIZE, INFO_JITSIZE:
		return uint64(use(re.code, func(p *C.pcre2_code) C.size_t {
			return infoSize(p, C.uint32_t(key))
		})), nil
	case INFO_ALLOPTIONS, INFO_ARGOPTIONS, INFO_BACKREFMAX, INFO_BSR,
		INFO_CAPTURECOUNT, INFO_DEPTHLIMIT, INFO_FIRSTCODETYPE,
		INFO_FIRSTCODEUNIT, INFO_HASBACKSLASHC, INFO_HASCRORLF,
		INFO_HEAPLIMIT, INFO_JCHANGED, INFO_LASTCODETYPE, INFO_LASTCODEUNIT,
		INFO_MATCHEMPTY, INFO_MATCHLIMIT, INFO_MAXLOOKBEHIND, INFO_MINLENGTH,
		INFO_NAMECOUNT, INFO_NAMEENTRYSIZE, INFO_NEWLINE:
		return uint64(use(re.code, func(p *C.pcre2_code) C.uint32_t {
			return info32(p, C.uint32_t(key))
		})), nil
	case INFO_NAMETABLE, INFO_FIRSTBITMAP:
		return 0, fmt.Errorf("pcre: Info(%d): pointer-valued key; use CaptureNames", key)
	}

	return 0, fmt.Errorf("pcre: Info(%d): unknown pattern info key", key)
}
