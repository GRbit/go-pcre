package pcre

import "testing"

// TestLinkedLibrary is the Phase 0 smoke test: the package compiles, links
// against libpcre2-8, and can call into it.
func TestLinkedLibrary(t *testing.T) {
	t.Logf("libpcre2-8 JIT support: %v", libJITSupported())
}
