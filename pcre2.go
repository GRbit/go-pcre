// Package pcre provides access to the Perl Compatible Regular Expression
// library, PCRE2 (10.x).
//
// This is v2 of github.com/GRbit/go-pcre, a port of the v1 API from the
// legacy PCRE 8.x library to PCRE2. The Regexp/Matcher surface is
// v1-compatible; intentional divergences are listed in the migration guide.
//
// Requirements: libpcre2-8 >= 10.34 (Debian/Ubuntu: apt install
// libpcre2-dev). Features that need a newer libpcre2 are gated to fail at
// build time rather than silently degrade.
package pcre

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#if PCRE2_MAJOR < 10 || (PCRE2_MAJOR == 10 && PCRE2_MINOR < 34)
#error "github.com/GRbit/go-pcre/v2 requires libpcre2-8 >= 10.34"
#endif
*/
import "C"

import "unsafe"

// libJITSupported reports whether the linked libpcre2-8 was built with JIT
// support. It exists in Phase 0 as a link-time smoke probe; Phase 3 builds
// the public JITAvailable on top of it.
func libJITSupported() bool {
	var jit C.uint32_t
	C.pcre2_config(C.PCRE2_CONFIG_JIT, unsafe.Pointer(&jit))
	return jit != 0
}
