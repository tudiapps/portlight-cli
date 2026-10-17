//go:build !windows

package i18n

// systemLanguage is empty: outside Windows the locale variables are the
// system language.
func systemLanguage() string { return "" }
