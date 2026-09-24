package pcre

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
*/
import "C"

import (
	"slices"
	"sort"
	"strings"
	"sync"
	"unsafe"
)

// CaptureName describes one named capture group: its name and group number.
type CaptureName struct {
	Name  string
	Index int
}

// nameTable is the pattern's name table parsed into Go once, so every
// lookup is a binary search instead of two cgo calls and a C malloc. The
// table is immutable for the life of the compiled pattern. Compile only
// allocates the empty struct (and only for patterns with named groups);
// the parse runs under once on first use, so compiling a pattern stays as
// cheap as before and the copy is paid only by code that looks names up.
type nameTable struct {
	once    sync.Once
	entries []CaptureName // table order: sorted by name, duplicates in group order
	nums    []int         // group numbers in entries order; lookup slices runs of it
}

// newNameTable returns the table placeholder for a freshly compiled
// pattern, or nil when it has no named groups.
func newNameTable(p *C.pcre2_code) *nameTable {
	if info32(p, C.PCRE2_INFO_NAMECOUNT) == 0 {
		return nil
	}

	return &nameTable{}
}

// table returns the pattern's parsed name table, parsing it on first use,
// or nil when the pattern has no named groups.
func (re Regexp) table() *nameTable {
	re.code.check()
	t := re.names
	if t == nil {
		return nil
	}
	t.once.Do(func() {
		use(re.code, func(p *C.pcre2_code) bool {
			t.parse(p)

			return true
		})
	})

	return t
}

// parse reads the 8-bit name table (unchanged from PCRE1, pcre2api.3: 2
// bytes of group number, most significant first, then the NUL-terminated
// name). Three allocations: one copy of the raw table, of which every name
// is a substring, the entries, and one backing array for the group
// number runs.
func (t *nameTable) parse(p *C.pcre2_code) {
	nameCount := int(info32(p, C.PCRE2_INFO_NAMECOUNT))
	entrySize := int(info32(p, C.PCRE2_INFO_NAMEENTRYSIZE))
	var table *C.PCRE2_UCHAR // the one pointer-valued key this package reads
	C.pcre2_pattern_info(p, C.PCRE2_INFO_NAMETABLE, unsafe.Pointer(&table))

	// The table is C memory inside the compiled pattern; it is copied out
	// whole while use keeps the pattern alive.
	raw := string(unsafe.Slice((*byte)(unsafe.Pointer(table)), nameCount*entrySize))
	t.entries = make([]CaptureName, nameCount)
	t.nums = make([]int, nameCount)
	for i := range nameCount {
		entry := raw[i*entrySize : (i+1)*entrySize]
		name := entry[2:]
		if n := strings.IndexByte(name, 0); n >= 0 {
			name = name[:n]
		}
		t.nums[i] = int(entry[0])<<8 | int(entry[1])
		t.entries[i] = CaptureName{Name: name, Index: t.nums[i]}
	}
}

// lookup returns the group numbers behind name, in table order, as a
// sub-slice of nums that callers must not modify, or nil. The name is cut
// at its first NUL because the C lookups this replaces
// (pcre2_substring_number_from_name via a C string) saw it that way.
// Duplicate names are adjacent in the table (it is sorted by name), so a
// binary search for the first entry and a scan forward find them all.
func (t *nameTable) lookup(name string) []int {
	if t == nil {
		return nil
	}
	if i := strings.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	first := sort.Search(len(t.entries), func(i int) bool { return t.entries[i].Name >= name })
	last := first
	for last < len(t.entries) && t.entries[last].Name == name {
		last++
	}
	if first == last {
		return nil
	}

	return t.nums[first:last:last]
}

// CaptureNames returns the named capturing parentheses of the pattern, in
// name-table order (sorted by name). With DUPNAMES a name can appear more
// than once, each with its own group number. The result is the caller's
// to modify.
func (re Regexp) CaptureNames() []CaptureName {
	t := re.table()
	if t == nil {
		return nil
	}

	return slices.Clone(t.entries)
}

// GroupNumbersForName returns the numbers of all capture groups using the
// given name - several with DUPNAMES, one for a unique name - or nil if no
// group has that name. New in v2; v1 could not enumerate duplicate names.
func (re Regexp) GroupNumbersForName(name string) []int {
	nums := re.table().lookup(name)
	if nums == nil {
		return nil
	}

	return slices.Clone(nums)
}
