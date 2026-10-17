// Package i18n picks the language of the CLI's messages: English, or
// Turkish when the system language is Turkish. PORTLIGHT_LANG (`en`, `tr`)
// overrides the system.
package i18n

import (
	"os"
	"strings"
	"sync"
)

// LangEnv names the environment variable that overrides the language.
const LangEnv = "PORTLIGHT_LANG"

var (
	once    sync.Once
	turkish bool
)

// Turkish reports whether messages are shown in Turkish.
func Turkish() bool {
	once.Do(func() { turkish = detect() })
	return turkish
}

// S returns en, or tr when messages are shown in Turkish.
func S(en, tr string) string {
	if Turkish() {
		return tr
	}
	return en
}

func detect() bool {
	if v := os.Getenv(LangEnv); v != "" {
		return isTurkish(v)
	}
	// POSIX order: LC_ALL wins over LC_MESSAGES, which wins over LANG.
	for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(name); v != "" && v != "C" && v != "POSIX" {
			return isTurkish(v)
		}
	}
	return isTurkish(systemLanguage())
}

// isTurkish reads a locale such as tr_TR.UTF-8, tr-TR or tr.
func isTurkish(locale string) bool {
	l := strings.ToLower(locale)
	return l == "tr" || strings.HasPrefix(l, "tr_") || strings.HasPrefix(l, "tr-") || strings.HasPrefix(l, "tr.")
}
