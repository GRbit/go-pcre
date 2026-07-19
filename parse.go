package pcre

import "fmt"

// parseFlagsRe matches a leading "(?letters)" candidate flag group.
var parseFlagsRe = MustCompile(`^\(\?[a-zA-Z]+?\)`, 0)

// flagLetters maps "(?flags)" letters to the compile flags they stand for.
// X maps to EXTRA == 0: PCRE2 is strict by default, so the letter is
// accepted for v1 compatibility and ignored.
var flagLetters = map[byte]int{
	'i': CASELESS,
	'D': DOLLAR_ENDONLY,
	's': DOTALL,
	'J': DUPNAMES,
	'x': EXTENDED,
	'X': EXTRA,
	'm': MULTILINE,
	'U': UNGREEDY,
	'u': UTF | UCP,
}

// ParseFlags returns string with regex pattern and int with pcre flags.
// Flags are specified before the regex in form like this "(?flags)regex"
// Supported symbols i=CASELESS; m=MULTILINE; s=DOTALL; U=UNGREEDY; J=DUPNAMES;
// x=EXTENDED; X=EXTRA (no-op in PCRE2); D=DOLLAR_ENDONLY; u=UTF|UCP;
//
// Caveat (kept for backward compatibility): every leading "(?letters)" group
// is consumed, and letters that are not flags are silently ignored. This
// means PCRE constructs made of letters only, such as "(?R)", are stripped
// from the beginning of the pattern rather than passed to pcre2_compile. Do
// not use ParseFlags/CompileParse with such patterns.
func ParseFlags(ptr string) (string, int) {
	flags := 0

	for {
		fStr := parseFlagsRe.FindString(ptr, 0)
		if fStr == "" {
			return ptr, flags
		}

		for i := 2; i < len(fStr)-1; i++ { // letters between "(?" and ")"
			flags |= flagLetters[fStr[i]] // unknown letters add nothing
		}

		ptr = ptr[len(fStr):]
	}
}

// CompileParse try to parse flags of regex and compile it. If an error occurs,
// the second return value is non-nil. Flags are specified before the regex in
// form like this "(?flags)regex"
func CompileParse(ptr string) (Regexp, error) {
	ptr, f := ParseFlags(ptr)
	retRegex, err := Compile(ptr, f)
	if err != nil {
		return Regexp{}, fmt.Errorf("can't compile/study pcre regexp: pattern='%s' flags='%b': %w", ptr, f, err)
	}

	return retRegex, nil
}

// CompileParseJIT try to parse flags of regex and compile it with JIT
// optimization. If an error occurs, the second return value is non-nil.
func CompileParseJIT(ptr string, flags int) (Regexp, error) {
	ptr, f := ParseFlags(ptr)
	retRegex, err := CompileJIT(ptr, f, flags)
	if err != nil {
		return Regexp{},
			fmt.Errorf("can't compile/study pcre regexp: pattern='%s' flags=%b flagsJIT=%b: %w",
				ptr, f, flags, err)
	}

	return retRegex, nil
}

// MustCompileParse is same as CompileParse but if compilation fails, panic.
func MustCompileParse(pattern string) (re Regexp) {
	re, err := CompileParse(pattern)
	if err != nil {
		panic(err)
	}

	return
}

// MustCompileParseJIT is same as CompileParseJIT but if compilation fails,
// panic.
func MustCompileParseJIT(pattern string, flags int) (re Regexp) {
	re, err := CompileParseJIT(pattern, flags)
	if err != nil {
		panic(err)
	}

	return
}
