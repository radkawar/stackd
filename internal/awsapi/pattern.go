package awsapi

import (
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/dlclark/regexp2"
)

var patternCache sync.Map

// Match complete escapes before brackets so literal backslashes and escaped
// character-class delimiters cannot change the meaning of a later escape.
// Adjacent high/low UTF-16 escapes form one scalar before other code points.
var patternEscape = regexp.MustCompile(`\\\\|\\u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4,6}|\\[pP]\{(?:Print|ASCII)\}|\\.|[\[\]]`)

func compiledPattern(pattern string) (*regexp2.Regexp, error) {
	if cached, ok := patternCache.Load(pattern); ok {
		return cached.(*regexp2.Regexp), nil
	}
	// AWS's model corpus includes BMP, UTF-16 pairs and unbraced supplementary
	// escapes. regexp2 matches runes and supports explicit ECMAScript Unicode
	// code points; retain the original pattern in the catalog.
	// https://github.com/dlclark/regexp2/blob/v1.12.0/README.md#ecmascript-compatibility-mode
	inClass := false
	normalized := patternEscape.ReplaceAllStringFunc(pattern, func(escape string) string {
		switch escape {
		case "[":
			inClass = true
			return escape
		case "]":
			inClass = false
			return escape
		case `\p{Print}`, `\P{Print}`, `\p{ASCII}`, `\P{ASCII}`:
			// Java POSIX classes are byte ranges, not Unicode categories.
			// Expand directly inside a class rather than nesting brackets.
			ranges, complement := `\x20-\x7E`, `\x00-\x1F\x7F-\u{10FFFF}`
			if escape == `\p{ASCII}` || escape == `\P{ASCII}` {
				ranges, complement = `\x00-\x7F`, `\x80-\u{10FFFF}`
			}
			if escape[1] == 'P' {
				ranges = complement
			}
			if inClass {
				return ranges
			}
			return "[" + ranges + "]"
		}
		if len(escape) < 6 {
			return escape
		}
		if len(escape) == 12 {
			high, _ := strconv.ParseInt(escape[2:6], 16, 32)
			low, _ := strconv.ParseInt(escape[8:], 16, 32)
			return fmt.Sprintf(`\u{%X}`, utf16.DecodeRune(rune(high), rune(low)))
		}
		return `\u{` + escape[2:] + `}`
	})
	compiled, err := regexp2.Compile(normalized, regexp2.ECMAScript|regexp2.Unicode)
	if err != nil {
		return nil, fmt.Errorf("compile modeled pattern: %w", err)
	}
	compiled.MatchTimeout = 50 * time.Millisecond
	actual, _ := patternCache.LoadOrStore(pattern, compiled)
	return actual.(*regexp2.Regexp), nil
}

func matchPattern(pattern, value string) (bool, error) {
	compiled, err := compiledPattern(pattern)
	if err != nil {
		return false, err
	}
	matched, err := compiled.MatchString(value)
	if err != nil {
		return false, fmt.Errorf("modeled pattern exceeded its match budget (%s characters)", strconv.Itoa(len(value)))
	}
	return matched, nil
}
