# v1 vs v2 differential report

Cases: 143, comparisons (case x axis): 608, runs with known diffs: 128, runs with UNEXPLAINED diffs: 0

## Unexplained differences

None.

## Known divergences observed

- **D11**: 8 diff(s); example: named/dupnames [jit-bytes]
- **D12**: 12 diff(s); example: empty/alt-empty-first [jit-bytes]
- **D2**: 4 diff(s); example: cerr/nul-in-pattern [jit-bytes]
- **D3**: 4 diff(s); example: quote/n-name [jit-bytes]
- **D4**: 84 diff(s); example: anchor/backslash-a [jit-bytes]
- **D4+D5+D12**: 8 diff(s); example: nl/anycrlf-dollar [jit-bytes]
- **D5**: 16 diff(s); example: nl/crlf-empty-advance [jit-bytes]
- **DIALECT:backref-digits**: 8 diff(s); example: backref/eight-literal [jit-bytes]
- **DIALECT:bare-x**: 4 diff(s); example: cerr/bare-x [jit-bytes]
- **DIALECT:branch-reset-names**: 4 diff(s); example: named/branch-reset-two-names [jit-bytes]
- **DIALECT:caseless-lc**: 32 diff(s); example: case/prop-lu [jit-bytes]
- **DIALECT:k-lookaround**: 4 diff(s); example: kesc/in-lookahead [jit-bytes]
- **DIALECT:n-codepoint**: 4 diff(s); example: quote/n-codepoint [jit-bytes]
- **DIALECT:name-length**: 4 diff(s); example: named/len-33 [jit-bytes]
- **DIALECT:new-inline-modifiers**: 8 diff(s); example: inline/caret-reset [jit-bytes]
- **FLAGS:no-start-optimize-compile-only**: 36 diff(s); example: flags/no-start-optimize-match-time [jit-bytes+NO_START_OPTIMIZE]

## Library configuration

### v1 (PCRE 8.x)

```
jit: 1
jittarget: x86 64bit (little endian + unaligned)
link_size: 2
match_limit: 10000000
match_limit_recursion: 10000000
newline: 10
bsr: 0
posix_malloc_threshold: 10
stackrecurse: 1
utf16: 0
utf32: 0
utf8: 1
unicode_properties: 1
```

### v2 (PCRE2, version 10.46 2025-08-27)

```
version: 10.46 2025-08-27
unicode: 1
unicode_version: 16.0.0
jit: 1
jittarget: x86 64bit (little endian + unaligned)
newline: 2
bsr: 1
link_size: 2
match_limit: 10000000
depth_limit: 10000000
heap_limit: 20000000
parens_limit: 250
compiled_widths: 7
```
