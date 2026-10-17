package i18n

import "golang.org/x/sys/windows"

// systemLanguage is the user's preferred Windows display language, such as
// tr-TR; Windows sets no LANG.
func systemLanguage() string {
	langs, err := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	if err != nil || len(langs) == 0 {
		return ""
	}
	return langs[0]
}
