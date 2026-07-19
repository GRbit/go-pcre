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

// parseFlags consumes leading "(?letters)" groups. In lenient mode unknown
// letters add nothing and the group is consumed anyway (v1 semantics); in
// strict mode the first group with an unknown letter is left in the
// pattern for the engine, and parsing stops there.
func parseFlags(ptr string, strict bool) (string, int) {
	flags := 0

	for {
		fStr := parseFlagsRe.FindString(ptr, 0)
		if fStr == "" {
			return ptr, flags
		}

		groupFlags := 0
		for i := 2; i < len(fStr)-1; i++ { // letters between "(?" and ")"
			f, known := flagLetters[fStr[i]]
			if !known && strict {
				return ptr, flags
			}
			groupFlags |= f
		}

		flags |= groupFlags
		ptr = ptr[len(fStr):]
	}
}

// ParseFlags returns string with regex pattern and int with pcre flags.
// Flags are specified before the regex in form like this "(?flags)regex"
// Supported symbols i=CASELESS; m=MULTILINE; s=DOTALL; U=UNGREEDY; J=DUPNAMES;
// x=EXTENDED; X=EXTRA (no-op in PCRE2); D=DOLLAR_ENDONLY; u=UTF|UCP;
//
// Caveat (kept for backward compatibility with v1): every leading
// "(?letters)" group is consumed, and letters that are not flags are
// silently ignored. This means PCRE constructs made of letters only, such
// as "(?R)", are stripped from the beginning of the pattern rather than
// passed to pcre2_compile, and misspellings like "(?gi)" quietly lose
// their unknown letters where Perl would report an error. Do not use
// ParseFlags/CompileParse with such patterns: use ParseFlagsStrict, or
// skip pre-parsing entirely, since PCRE2 itself understands Perl's inline
// modifiers (see Compile), which is the most Perl-compatible route.
func ParseFlags(ptr string) (string, int) {
	return parseFlags(ptr, false)
}

// ParseFlagsStrict is the Perl-compatible variant of ParseFlags: it
// consumes a leading "(?letters)" group only when every letter is a known
// flag letter (the set documented at ParseFlags). A group containing any
// other letter, such as "(?R)" recursion or a misspelling like "(?gi)", is
// left in the pattern for pcre2_compile to interpret, which either gives
// it its real PCRE2 meaning or rejects it exactly as Perl would. Parsing
// stops at the first non-flag group.
func ParseFlagsStrict(ptr string) (string, int) {
	return parseFlags(ptr, true)
}

// CompileParse try to parse flags of regex and compile it. If an error occurs,
// the second return value is non-nil: it keeps the v1 message prefix and
// wraps the *CompileError, so errors.As reaches the message and offset.
// Flags are specified before the regex in form like this "(?flags)regex"
//
// The flag parsing is ParseFlags' lenient, v1-compatible kind; see the
// caveat there. For Perl-compatible handling use CompileParseStrict, or
// plain Compile with the modifiers written inside the pattern.
func CompileParse(ptr string) (Regexp, error) {
	ptr, f := ParseFlags(ptr)
	retRegex, err := Compile(ptr, f)
	if err != nil {
		return Regexp{}, fmt.Errorf("can't compile/study pcre regexp: pattern='%s' flags='%b': %w", ptr, f, err)
	}

	return retRegex, nil
}

// CompileParseStrict parses leading "(?flags)" groups with
// ParseFlagsStrict and compiles the rest. Unlike CompileParse it keeps
// Perl semantics (non-flag groups such as "(?R)" reach the engine intact,
// invalid modifier groups fail compilation with a *CompileError) and it
// returns Compile's error unwrapped.
func CompileParseStrict(ptr string) (Regexp, error) {
	pat, f := ParseFlagsStrict(ptr)

	return Compile(pat, f)
}

// CompileParseJIT try to parse flags of regex and compile it with JIT
// optimization. If an error occurs, the second return value is non-nil.
// The flag parsing is the lenient v1 kind; see ParseFlags.
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
