package eventpattern

import (
	"regexp"
	"strings"
	"unicode/utf16"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Case-insensitive EventBridge expressions offer the full lower/upper mapping
// of each pattern character. These are alternatives, not normalization of the
// event: a pattern ß matches SS but not ss. Native fixtures also retain the
// UTF-16 unit behavior of AWS's parser, including replacement of surrogate units.
func caseInsensitive(pattern, operator string) (*regexp.Regexp, error) {
	lower, upper := cases.Lower(language.Und), cases.Upper(language.Und)
	var expression strings.Builder
	if operator != "suffix" {
		expression.WriteString("\\A")
	}
	for _, unit := range utf16.Encode([]rune(pattern)) {
		if utf16.IsSurrogate(rune(unit)) {
			expression.WriteString(`\?`)
			continue
		}
		character := string(rune(unit))
		lo, hi := lower.String(character), upper.String(character)
		if lo == hi {
			expression.WriteString(regexp.QuoteMeta(lo))
		} else {
			expression.WriteString("(?:" + regexp.QuoteMeta(lo) + "|" + regexp.QuoteMeta(hi) + ")")
		}
	}
	if operator != "prefix" {
		expression.WriteString("\\z")
	}
	return regexp.Compile(expression.String())
}
