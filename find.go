package pcre

// bumpAlong returns the next start offset when the iteration protocol must
// advance without progress from a match: past a CRLF pair as one atomic
// unit when the pattern's newline convention says CRLF is a newline, else
// one whole character in UTF mode, else one code unit. This mirrors
// do_bumpalong in pcre2_match_next.c (and pcre2_substitute's advance).
func (re *Regexp) bumpAlong(subject []byte, offset int) int {
	if re.crlfNewline && subject[offset] == '\r' &&
		offset+1 < len(subject) && subject[offset+1] == '\n' {
		return offset + 2
	}

	next := offset + 1
	if re.utf {
		for next < len(subject) && subject[next]&0xC0 == 0x80 {
			next++ // skip UTF-8 continuation bytes
		}
	}

	return next
}

// iterate runs the canonical global-match protocol (pcredemo.c, now
// codified in pcre2_match_next.c): after an empty match, retry at the same
// offset requiring a non-empty match (NOTEMPTY_ATSTART|ANCHORED); when the
// retry fails, bump along one character and resume the normal search.
// Matching uses a native start offset over the whole subject, so ^, \b and
// lookbehind see the true context at every iteration boundary. yield
// receives each match's offsets; returning false stops the iteration.
func (re *Regexp) iterate(m *Matcher, subject []byte, flags int, yield func(start, end int) bool) {
	offset, retry := 0, false
	for offset <= len(subject) {
		f := flags
		if retry {
			f |= NOTEMPTY_ATSTART | ANCHORED
		}
		if !m.matchWithOffset(subject, offset, f) {
			if !retry {
				return // definitive no-match (or error in m.Error)
			}
			// No non-empty match at this offset: step past it.
			offset = re.bumpAlong(subject, offset)
			retry = false

			continue
		}

		start, end := int(m.ovector[0]), int(m.ovector[1])
		if end < start || start < offset {
			// \K inside a lookaround moved the match start after its own end
			// or before the search offset (compiles only on libpcre2 < 10.38).
			// Such offsets cannot be sliced or advanced from sanely: abandon
			// the run, as pcre2demo.c does and as pcre2_substitute does with
			// BADSUBSPATTERN.
			return
		}
		if !yield(start, end) {
			return
		}

		if start != end {
			offset = end // end > offset here, so this is progress
			retry = false

			continue
		}
		// Empty match: done at the end of the subject, otherwise demand a
		// non-empty match at this same offset next round.
		if end >= len(subject) {
			return
		}
		offset = end
		retry = true
	}
}

// FindAllIndex returns successive matches of the expression as pairs of
// byte offsets, or nil if there is no match.
//
// Iteration uses a native start offset instead of v1's re-slicing, so ^,
// \b/\B and lookbehind behave correctly at iteration boundaries, and the
// empty-match advance steps whole characters in UTF mode (intentional v2
// divergences, pinned by TestFindAllIndex).
func (re *Regexp) FindAllIndex(bytes []byte, flags int) (r [][]int) {
	m := re.matcherFromPool()
	defer re.putMatcher(m)
	re.iterate(m, bytes, flags, func(start, end int) bool {
		r = append(r, []int{start, end})

		return true
	})

	return
}

// FindIndex returns the start and end of the first match, or nil if no match.
// loc[0] is the start and loc[1] is the end.
func (re *Regexp) FindIndex(bytes []byte, flags int) []int {
	m := re.matcherFromPool()
	defer re.putMatcher(m)

	if m.matchWithOffset(bytes, 0, flags) {
		return []int{int(m.ovector[0]), int(m.ovector[1])}
	}

	return nil
}

// FindString returns the text of the first match, or "" if there is no
// match. Note that "" is also returned for a valid empty-width match, so a
// zero result does not necessarily mean the pattern did not match; use
// FindIndex to distinguish the two.
func (re *Regexp) FindString(s string, flags int) string {
	m := re.matcherFromPool()
	defer re.putMatcher(m)

	if m.matchWithOffset([]byte(s), 0, flags) {
		return s[int(m.ovector[0]):int(m.ovector[1])]
	}

	return ""
}
