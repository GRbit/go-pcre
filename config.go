package pcre

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
*/
import "C"

import (
	"fmt"
	"strconv"
	"unsafe"
)

// Config returns information about the linked libpcre2 build as a string.
// Numeric queries (uniformly uint32 in PCRE2) are rendered in decimal;
// VERSION, UNICODE_VERSION and JITTARGET are returned as text. Unknown
// keys - and JITTARGET on a JIT-less library (BADOPTION) - return "".
// C docs: https://www.pcre.org/current/doc/html/pcre2_config.html
func Config(f int) string {
	switch f {
	case CONFIG_VERSION, CONFIG_UNICODE_VERSION, CONFIG_JITTARGET:
		// String protocol: a NULL where-pointer asks for the required
		// buffer size in code units, including the trailing NUL.
		n := C.pcre2_config(C.uint32_t(f), nil)
		if n <= 0 {
			return ""
		}
		buf := make([]byte, int(n))
		C.pcre2_config(C.uint32_t(f), unsafe.Pointer(&buf[0]))

		return string(buf[:n-1])
	}

	var v C.uint32_t
	if C.pcre2_config(C.uint32_t(f), unsafe.Pointer(&v)) < 0 {
		return ""
	}

	return strconv.FormatUint(uint64(v), 10)
}

// ConfigAll returns a string with all information available through
// pcre2_config, one "key: value" per line.
func ConfigAll() string {
	ret := ""
	for _, c := range []struct {
		name string
		key  int
	}{
		{"version", CONFIG_VERSION},
		{"unicode", CONFIG_UNICODE},
		{"unicode_version", CONFIG_UNICODE_VERSION},
		{"jit", CONFIG_JIT},
		{"jittarget", CONFIG_JITTARGET},
		{"newline", CONFIG_NEWLINE},
		{"bsr", CONFIG_BSR},
		{"link_size", CONFIG_LINKSIZE},
		{"match_limit", CONFIG_MATCHLIMIT},
		{"depth_limit", CONFIG_DEPTHLIMIT},
		{"heap_limit", CONFIG_HEAPLIMIT},
		{"parens_limit", CONFIG_PARENSLIMIT},
		{"compiled_widths", CONFIG_COMPILED_WIDTHS},
	} {
		ret += fmt.Sprintf("%s: %s\n", c.name, Config(c.key))
	}

	return ret
}
