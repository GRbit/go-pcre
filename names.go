package pcre

/*
#cgo pkg-config: libpcre2-8
#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdlib.h>
#include <pcre2.h>
*/
import "C"

import (
	"bytes"
	"unsafe"
)

// CaptureName describes one named capture group: its name and group number.
type CaptureName struct {
	Name  string
	Index int
}

// CaptureNames returns the named capturing parentheses of the pattern, in
// name-table order (sorted by name). With DUPNAMES a name can appear more
// than once, each with its own group number.
//
// The 8-bit name table format is unchanged from PCRE1 (pcre2api.3): each
// entry is 2 bytes of group number, most significant first, followed by
// the NUL-terminated name.
func (re Regexp) CaptureNames() []CaptureName {
	return use(re.code, func(p *C.pcre2_code) []CaptureName {
		var nameCount, entrySize C.uint32_t
		var table *C.PCRE2_UCHAR
		C.pcre2_pattern_info(p, C.PCRE2_INFO_NAMECOUNT, unsafe.Pointer(&nameCount))
		if nameCount == 0 {
			return nil
		}
		C.pcre2_pattern_info(p, C.PCRE2_INFO_NAMEENTRYSIZE, unsafe.Pointer(&entrySize))
		C.pcre2_pattern_info(p, C.PCRE2_INFO_NAMETABLE, unsafe.Pointer(&table))

		// The table is C memory inside the compiled pattern; all names are
		// copied out (string(...)) before use releases it.
		raw := unsafe.Slice((*byte)(unsafe.Pointer(table)), int(nameCount)*int(entrySize))
		result := make([]CaptureName, 0, int(nameCount))
		for i := 0; i < int(nameCount); i++ {
			entry := raw[i*int(entrySize) : (i+1)*int(entrySize)]
			name := entry[2:]
			if n := bytes.IndexByte(name, 0); n >= 0 {
				name = name[:n]
			}
			result = append(result, CaptureName{
				Name:  string(name),
				Index: int(entry[0])<<8 | int(entry[1]),
			})
		}

		return result
	})
}

// GroupNumbersForName returns the numbers of all capture groups using the
// given name - several with DUPNAMES, one for a unique name - or nil if no
// group has that name. New in v2 (pcre2_substring_nametable_scan); v1 could
// not enumerate duplicate names.
func (re Regexp) GroupNumbersForName(name string) []int {
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	return use(re.code, func(code *C.pcre2_code) []int {
		var first, last C.PCRE2_SPTR8 // const PCRE2_UCHAR*, cgo's spelling
		rc := C.pcre2_substring_nametable_scan(code,
			(*C.PCRE2_UCHAR)(unsafe.Pointer(nameC)), &first, &last)
		if rc < 0 {
			return nil
		}

		// first/last point at the first and last matching name-table
		// entries inside the pattern; rc is the entry size.
		nums := make([]int, 0, 2)
		for p := unsafe.Pointer(first); uintptr(p) <= uintptr(unsafe.Pointer(last)); p = unsafe.Add(p, int(rc)) {
			entry := (*[2]byte)(p)
			nums = append(nums, int(entry[0])<<8|int(entry[1]))
		}

		return nums
	})
}
