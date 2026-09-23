package pcre

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// JITAvailable reports whether the linked libpcre2-8 was built with JIT
// support (pcre2_config(PCRE2_CONFIG_JIT)). When it returns false, Study
// and CompileJIT return errors instead of silently matching without JIT -
// the failure mode v1 shipped with.
func JITAvailable() bool {
	var jit C.uint32_t
	C.pcre2_config(C.PCRE2_CONFIG_JIT, unsafe.Pointer(&jit))

	return jit != 0
}

// JITCompiled reports whether JIT code was actually generated for this
// pattern (PCRE2_INFO_JITSIZE non-zero). Even a successful Study can
// produce no JIT code when the pattern uses items the JIT does not
// support; this is the observable truth.
func (re Regexp) JITCompiled() bool {
	return use(re.code, func(p *C.pcre2_code) bool {
		return infoSize(p, C.PCRE2_INFO_JITSIZE) != 0
	})
}

// Study JIT-compiles the pattern (pcre2_jit_compile), which gives a large
// matching speed boost. flags is a combination of the JIT_* constants (the
// v1 STUDY_* names are aliases). Study(0), v1's non-JIT study, is a
// successful no-op: PCRE2 computes that optimization data at compile time.
//
// Study mutates the compiled pattern in place: it must complete before the
// Regexp is shared with other goroutines. Calling it concurrently with
// matching, or with another Study of the same Regexp, is a data race.
func (re *Regexp) Study(flags int) error {
	if flags == 0 {
		return nil
	}

	if re.JITCompiled() {
		return errors.New("regexp already optimized")
	}

	rc := use(re.code, func(p *C.pcre2_code) C.int {
		return C.pcre2_jit_compile(p, C.uint32_t(flags))
	})
	if rc != 0 {
		return fmt.Errorf("pcre2_jit_compile (%d): %s", int(rc), errorMessage(rc))
	}

	return nil
}

// CompileJIT compiles pattern and JIT-compiles the result. flagsC is
// Compile flags, flagsS is Study flags, which must include
// JIT_COMPLETE/STUDY_JIT_COMPILE.
func CompileJIT(pattern string, flagsC, flagsS int) (Regexp, error) {
	re, err := Compile(pattern, flagsC)
	if err != nil {
		return re, err
	}

	if (flagsS & JIT_COMPLETE) == 0 {
		return re, errors.New("flagsS must contain the pcre.JIT_COMPLETE (STUDY_JIT_COMPILE) flag")
	}

	if errS := re.Study(flagsS); errS != nil {
		return re, fmt.Errorf("study error: %w", errS)
	}

	return re, nil
}

// MustCompileJIT is same as CompileJIT but if compilation fails, panic.
func MustCompileJIT(pattern string, flagsC, flagsS int) (re Regexp) {
	re, err := CompileJIT(pattern, flagsC, flagsS)
	if err != nil {
		panic(err)
	}

	return
}
