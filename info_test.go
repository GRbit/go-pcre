package pcre

import (
	"testing"
)

func TestInfo(t *testing.T) {
	re := MustCompile(`(?<a>abc)(d)?`, 0)

	want := map[string]struct {
		key int
		val uint64
	}{
		"capturecount":  {INFO_CAPTURECOUNT, uint64(re.Groups())},
		"minlength":     {INFO_MINLENGTH, 3},
		"namecount":     {INFO_NAMECOUNT, 1},
		"maxlookbehind": {INFO_MAXLOOKBEHIND, 0},
		"jitsize":       {INFO_JITSIZE, 0}, // not studied yet
	}
	for name, w := range want {
		got, err := re.Info(w.key)
		if err != nil || got != w.val {
			t.Errorf("Info(%s) = %d, %v; want %d", name, got, err, w.val)
		}
	}

	// INFO_SIZE is size_t-valued and must come back through the wide path.
	if size, err := re.Info(INFO_SIZE); err != nil || size == 0 {
		t.Errorf("Info(INFO_SIZE) = %d, %v; want a non-zero size", size, err)
	}

	for _, key := range []int{INFO_NAMETABLE, INFO_FIRSTBITMAP, 9999} {
		if _, err := re.Info(key); err == nil {
			t.Errorf("Info(%d): want an error for a pointer-valued or unknown key", key)
		}
	}

	if JITAvailable() {
		if err := re.Study(JIT_COMPLETE); err != nil {
			t.Fatal(err)
		}
		if size, err := re.Info(INFO_JITSIZE); err != nil || size == 0 {
			t.Errorf("Info(INFO_JITSIZE) after Study = %d, %v; want non-zero", size, err)
		}
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("Info on a zero Regexp: want a panic")
		}
	}()
	var zero Regexp
	_, _ = zero.Info(INFO_MINLENGTH)
}
