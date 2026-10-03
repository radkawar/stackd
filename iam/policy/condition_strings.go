package policy

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// IAM compares lowercased strings, rather than Unicode case-fold equivalents.
// Casing includes contextual final sigma and expanding dotted I, but preserves
// supplementary characters while retaining their influence on casing context.
// See the native string-condition captures in docs/iam-evaluation.md.
func conditionLower(text string) string {
	lowered := cases.Lower(language.Und).String(text)
	if strings.IndexFunc(text, func(r rune) bool { return r > 0xffff }) < 0 {
		return lowered
	}
	var result strings.Builder
	for _, r := range lowered {
		if r > 0xffff {
			for index, original := range text {
				if original > 0xffff {
					r = original
					text = text[index+utf8.RuneLen(original):]
					break
				}
			}
		}
		result.WriteRune(r)
	}
	return result.String()
}
