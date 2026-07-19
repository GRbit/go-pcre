package pcre

import (
	"reflect"
	"testing"
	"time"
)

func TestFind(t *testing.T) {
	re := MustCompile("b(c)d", 0)
	if got := re.FindIndex([]byte("abcdef"), 0); !reflect.DeepEqual(got, []int{1, 4}) {
		t.Errorf("FindIndex = %v, want [1 4]", got)
	}
	if got := re.FindString("abcdef", 0); got != "bcd" {
		t.Errorf("FindString = %q, want bcd", got)
	}
	if re.FindIndex([]byte("xyz"), 0) != nil || re.FindString("xyz", 0) != "" {
		t.Error("FindIndex/FindString should return nil/\"\" on no match")
	}
}

func TestFindAllIndex(t *testing.T) {
	// The rows pin the global-match protocol (MIGRATION.md D4, D5):
	// iteration drives a native start offset over the whole subject, so ^,
	// \b/\B and lookbehind see the true context at every boundary (v1
	// re-sliced the subject and got these wrong); the empty-match advance
	// steps whole characters in UTF mode. A watchdog turns an infinite loop into a failure.
	cases := []struct {
		pattern, subject string
		flags            int
		want             [][]int
	}{
		{"foo", "food fight fools foo", 0, [][]int{{0, 3}, {11, 14}, {17, 20}}},
		{"foo", "xyz", 0, nil},
		// Empty matches at every position, once each (v1 looped forever).
		{"", "abc", 0, [][]int{{0, 0}, {1, 1}, {2, 2}, {3, 3}}},
		// D4: ^ anchors to the real subject start; v1 found it at every restart.
		{`^.`, "abc", 0, [][]int{{0, 1}}},
		// D4: \B sees the character before the offset (pcre2_match.3's own example).
		{`\Biss`, "Mississippi", 0, [][]int{{1, 4}, {4, 7}}},
		// D4: lookbehind can inspect before the start offset.
		{`(?<=a)a`, "aaa", 0, [][]int{{1, 2}, {2, 3}}},
		// D5: "a" + e-acute (2 bytes): no empty match inside the character.
		{`x*`, "a\xc3\xa9", UTF, [][]int{{0, 0}, {1, 1}, {3, 3}}},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, c := range cases {
			re := MustCompile(c.pattern, c.flags)
			got := re.FindAllIndex([]byte(c.subject), 0)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("FindAllIndex(%q, %q) = %v, want %v", c.pattern, c.subject, got, c.want)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("FindAllIndex appears to hang (infinite loop)")
	}
}

func TestIterateAbandonsBackwardsKMatch(t *testing.T) {
	// \K inside a lookaround can set the match start after its own end
	// ((?=ab\K)) or before the search offset ((?<=\Kab)). libpcre2 >= 10.38
	// rejects both at compile time, so this runs only on older libraries
	// (the 10.34 floor included). There the iteration must abandon the run
	// instead of reporting unusable offsets, and ReplaceAll must not slice
	// backwards; pcre2_substitute refuses the same matches with
	// BADSUBSPATTERN. The ReplaceAll results equal v1's.
	cases := []struct {
		pattern, subject string
		wantIdx          [][]int
		wantRepl         string
	}{
		{`(?=ab\K)`, "ab", nil, "ab"},
		{`(?=ab\K)`, "xab", nil, "xab"},
		{`(?<=\Kab)`, "ab", [][]int{{0, 2}}, "-"},
		{`(?<=\Kab)`, "abx", [][]int{{0, 2}}, "-x"},
		{`(?<=\Kab)`, "xabx", [][]int{{1, 3}}, "x-x"},
	}
	for _, c := range cases {
		re, err := Compile(c.pattern, 0)
		if err != nil {
			t.Skipf("%s does not compile on this libpcre2 (>= 10.38 rejects \\K in lookarounds): %v", c.pattern, err)
		}
		if got := re.FindAllIndex([]byte(c.subject), 0); !reflect.DeepEqual(got, c.wantIdx) {
			t.Errorf("FindAllIndex(%s, %q) = %v, want %v", c.pattern, c.subject, got, c.wantIdx)
		}
		if got := re.ReplaceAllString(c.subject, "-", 0); got != c.wantRepl {
			t.Errorf("ReplaceAllString(%s, %q) = %q, want %q", c.pattern, c.subject, got, c.wantRepl)
		}
	}
}
