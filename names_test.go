package pcre

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestNames(t *testing.T) {
	re := MustCompile("(?<name2>a)(b)(c)(?<n1>d)", 0)
	names := re.CaptureNames()
	if len(names) != 2 {
		t.Error("Names count", len(names))
	}
	if names[0].Name != "n1" {
		t.Error("Names name 1", names[0].Name)
	}
	if names[1].Name != "name2" {
		t.Error("Names name 2", names[1].Name)
	}
	if names[0].Index != 4 {
		t.Error("Names index 1", names[0].Index)
	}
	if names[1].Index != 1 {
		t.Error("Names index 2", names[1].Index)
	}

	// Have no named capturing
	re = MustCompile("(a)bc", 0)
	names = re.CaptureNames()
	if len(names) != 0 {
		t.Error("Names count", len(names))
	}
}

func TestNamesDuplicates(t *testing.T) {
	// New in v2: duplicate names (DUPNAMES) are first-class. A lookup of a
	// non-unique name through Named* fails with a distinct, detectable
	// error, and GroupNumbersForName enumerates all groups behind a name
	// (pcre2_substring_nametable_scan; v1 had no equivalent).
	re := MustCompile(`(?<n>a)|(?<n>b)`, DUPNAMES)

	m := re.NewMatcherString("b", 0)
	if !m.Matches {
		t.Fatal("should match")
	}

	if _, err := m.NamedString("n"); !errors.Is(err, ErrNonUniqueName) {
		t.Errorf("NamedString on duplicate name: err = %v, want ErrNonUniqueName", err)
	}
	if _, err := m.NamedString("zzz"); err == nil || errors.Is(err, ErrNonUniqueName) {
		t.Errorf("NamedString on unknown name: err = %v, want plain unknown-name error", err)
	}

	if got, want := re.GroupNumbersForName("n"), []int{1, 2}; !reflect.DeepEqual(got, want) {
		t.Errorf("GroupNumbersForName(n) = %v, want %v", got, want)
	}
	if got := re.GroupNumbersForName("zzz"); got != nil {
		t.Errorf("GroupNumbersForName(zzz) = %v, want nil", got)
	}

	// The duplicate groups are then addressable by number as usual.
	if !m.Present(2) || m.GroupString(2) != "b" {
		t.Error("group 2 should hold the b match")
	}

	// Unique names keep working through the same scan.
	re = MustCompile(`(?<x>a)(?<y>b)`, 0)
	if got, want := re.GroupNumbersForName("y"), []int{2}; !reflect.DeepEqual(got, want) {
		t.Errorf("GroupNumbersForName(y) = %v, want %v", got, want)
	}
}

func TestNamedCutsNameAtNUL(t *testing.T) {
	// The Go name table keeps the semantics of the C string lookup it
	// replaced: the name ends at its first NUL.
	re := MustCompile(`(?<host>\w+)`, 0)
	m := re.NewMatcherString("abc", 0)
	if got, err := m.NamedString("host\x00junk"); err != nil || got != "abc" {
		t.Errorf("NamedString(host NUL junk) = %q, %v; want abc", got, err)
	}
	if got := re.GroupNumbersForName("host\x00"); len(got) != 1 || got[0] != 1 {
		t.Errorf("GroupNumbersForName(host NUL) = %v, want [1]", got)
	}
}

func TestNameTableConcurrentFirstUse(t *testing.T) {
	// The name table is parsed lazily on first use; concurrent first uses
	// from several goroutines must parse once and all see the same table
	// (run under -race).
	re := MustCompile(`(?<user>\w+)@(?<host>\w+)`, 0)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := re.NewMatcherString("bob@example", 0)
			if s, err := m.NamedString("host"); err != nil || s != "example" {
				t.Errorf("NamedString = %q, %v", s, err)
			}
			if names := re.CaptureNames(); len(names) != 2 || names[0].Name != "host" {
				t.Errorf("CaptureNames = %v", names)
			}
		}()
	}
	wg.Wait()
}
