package i18n

import "testing"

func TestIsTurkish(t *testing.T) {
	for locale, want := range map[string]bool{
		"tr":          true,
		"tr_TR.UTF-8": true,
		"tr-TR":       true,
		"TR_tr":       true,
		"en_US.UTF-8": false,
		"en-GB":       false,
		"trk":         false,
		"":            false,
	} {
		if got := isTurkish(locale); got != want {
			t.Errorf("isTurkish(%q) = %t, want %t", locale, got, want)
		}
	}
}

func TestDetectPrefersOverride(t *testing.T) {
	t.Setenv("LC_ALL", "tr_TR.UTF-8")
	t.Setenv(LangEnv, "en")
	if detect() {
		t.Fatal("PORTLIGHT_LANG=en must win over LC_ALL=tr")
	}
	t.Setenv(LangEnv, "tr")
	if !detect() {
		t.Fatal("PORTLIGHT_LANG=tr must select Turkish")
	}
}

func TestDetectReadsLocaleVariables(t *testing.T) {
	t.Setenv(LangEnv, "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "tr_TR.UTF-8")
	if !detect() {
		t.Fatal("LANG=tr_TR must select Turkish")
	}
	t.Setenv("LC_ALL", "en_US.UTF-8")
	if detect() {
		t.Fatal("LC_ALL=en_US must win over LANG=tr_TR")
	}
}
