// Package regex provides the evaluator's ECMAScript regular-expression
// boundary. RE2 is used only for a conservative syntax subset; patterns that
// need ECMAScript constructs use regexp2's ECMAScript mode.
package regex

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

const fallbackTimeoutCheckPeriod = 5 * time.Millisecond

const contextFallbackTimeout = 10 * time.Millisecond

func init() {
	// regexp2 requires one process-wide clock for timeout checks. A short,
	// fixed period bounds synchronous cancellation latency. The clock is shared
	// by all fallback matches; this package never launches per-match workers.
	regexp2.SetTimeoutCheckPeriod(fallbackTimeoutCheckPeriod)
}

type Pattern struct {
	source           string
	legacySource     string
	flags            string
	options          regexp2.RegexOptions
	legacyIgnoreCase bool
	re2              *regexp.Regexp
	asciiRe2         *regexp.Regexp
	js               *regexp2.Regexp
	contextJS        *regexp2.Regexp
}

type CompileError struct {
	Code    string
	Message string
}

func (e *CompileError) Error() string { return e.Message }

func CompileLiteral(literal string) (Pattern, error) {
	source, flags, err := splitLiteral(literal)
	if err != nil {
		return Pattern{}, err
	}
	if source == "" {
		return Pattern{}, &CompileError{Code: "S0301", Message: "regular expression cannot be empty"}
	}
	var jsOptions regexp2.RegexOptions = regexp2.ECMAScript
	seenFlags := make(map[rune]bool, len(flags))
	for _, flag := range flags {
		if seenFlags[flag] {
			return Pattern{}, &CompileError{Code: "S0302", Message: fmt.Sprintf("duplicate regular expression flag %q", flag)}
		}
		seenFlags[flag] = true
		switch flag {
		case 'i':
			jsOptions |= regexp2.IgnoreCase
		case 'm':
		default:
			return Pattern{}, &CompileError{Code: "S0302", Message: fmt.Sprintf("unsupported regular expression flag %q", flag)}
		}
	}
	legacyIgnoreCase := strings.ContainsRune(flags, 'i')
	legacySource := source
	if legacyIgnoreCase {
		source = normalizeLegacyIgnoreCaseSource(source, '\ue000', '\ue001')
	}
	fallbackSource := translateECMAScriptPattern(source, strings.ContainsRune(flags, 'm'))
	js, jsErr := regexp2.Compile(fallbackSource, jsOptions)
	if jsErr != nil {
		return Pattern{}, &CompileError{Code: "S0302", Message: jsErr.Error()}
	}
	pattern := Pattern{source: fallbackSource, legacySource: legacySource, flags: flags, options: jsOptions, legacyIgnoreCase: legacyIgnoreCase, js: js}
	if re2Compatible(source, flags) {
		translated := source
		for _, flag := range flags {
			if strings.ContainsRune("ims", flag) {
				translated = "(?" + string(flag) + ")" + translated
			}
		}
		if re2, re2Err := regexp.Compile(translated); re2Err == nil {
			pattern.re2 = re2
		}
	}
	if asciiRE2IgnoreCaseCompatible(legacySource, flags) {
		if re2, re2Err := regexp.Compile("(?i)" + legacySource); re2Err == nil {
			pattern.asciiRe2 = re2
		}
	}
	if pattern.re2 == nil {
		contextJS, contextErr := regexp2.Compile(fallbackSource, jsOptions)
		if contextErr != nil {
			return Pattern{}, &CompileError{Code: "S0302", Message: contextErr.Error()}
		}
		contextJS.MatchTimeout = contextFallbackTimeout
		pattern.contextJS = contextJS
	}
	return pattern, nil
}

func translateECMAScriptPattern(source string, multiline bool) string {
	var translated strings.Builder
	escaped, inClass := false, false
	for _, char := range source {
		if escaped {
			if char > 0xffff {
				high, low := utf16Surrogates(char)
				_, _ = fmt.Fprintf(&translated, `\u%04x\u%04x`, high, low)
			} else {
				translated.WriteByte('\\')
				translated.WriteRune(char)
			}
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char > 0xffff {
			high, low := utf16Surrogates(char)
			_, _ = fmt.Fprintf(&translated, `\u%04x\u%04x`, high, low)
			continue
		}
		switch char {
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '.':
			if !inClass {
				translated.WriteString(`[^\r\n\u2028\u2029]`)
				continue
			}
		case '^':
			if !inClass {
				if multiline {
					translated.WriteString(`(?:\A|(?<=[\r\n\u2028\u2029]))`)
				} else {
					translated.WriteString(`\A`)
				}
				continue
			}
		case '$':
			if !inClass {
				if multiline {
					translated.WriteString(`(?:\z|(?=[\r\n\u2028\u2029]))`)
				} else {
					translated.WriteString(`\z`)
				}
				continue
			}
		}
		translated.WriteRune(char)
	}
	if escaped {
		translated.WriteByte('\\')
	}
	return translated.String()
}

func normalizeLegacyIgnoreCaseSource(text string, kelvinMarker, longSMarker rune) string {
	var out strings.Builder
	for index := 0; index < len(text); {
		if text[index] == '\\' {
			start := index
			for index < len(text) && text[index] == '\\' {
				index++
			}
			backslashes := index - start
			if backslashes%2 == 1 && index+5 <= len(text) && text[index] == 'u' {
				code := text[index+1 : index+5]
				switch code {
				case "017f", "017F":
					out.WriteString(strings.Repeat("\\", backslashes-1))
					out.WriteRune(longSMarker)
					index += 5
					continue
				case "212a", "212A":
					out.WriteString(strings.Repeat("\\", backslashes-1))
					out.WriteRune(kelvinMarker)
					index += 5
					continue
				}
			}
			out.WriteString(text[start:index])
			continue
		}
		r, size := utf8.DecodeRuneInString(text[index:])
		switch r {
		case 'K':
			out.WriteRune(kelvinMarker)
		case 'ſ':
			out.WriteRune(longSMarker)
		default:
			out.WriteRune(r)
		}
		index += size
	}
	return out.String()
}

func normalizeLegacyIgnoreCaseInput(text string, kelvinMarker, longSMarker rune) string {
	return strings.NewReplacer("K", string(kelvinMarker), "ſ", string(longSMarker)).Replace(text)
}

func normalizeLegacyIgnoreCase(text string) string {
	return normalizeLegacyIgnoreCaseInput(text, '\ue000', '\ue001')
}

func markerUsed(text string, marker rune) bool {
	if strings.ContainsRune(text, marker) {
		return true
	}
	escape := fmt.Sprintf("\\u%04x", marker)
	return strings.Contains(strings.ToLower(text), escape)
}

func legacyMarkers(source, input string) (rune, rune) {
	for marker := rune(0xe000); marker <= 0xf8ff-1; marker += 2 {
		if marker+1 <= 0xf8ff && !markerUsed(source, marker) && !markerUsed(source, marker+1) && !strings.ContainsRune(input, marker) && !strings.ContainsRune(input, marker+1) {
			return marker, marker + 1
		}
	}
	return '\ue000', '\ue001'
}

func (p Pattern) fallbackEngine(input string) (*regexp2.Regexp, []rune, error) {
	if !p.legacyIgnoreCase {
		return p.js, utf16Runes(input), nil
	}
	markerK, markerS := legacyMarkers(p.legacySource, input)
	if markerK == '\ue000' && markerS == '\ue001' && !markerUsed(p.legacySource, markerK) && !markerUsed(p.legacySource, markerS) && !strings.ContainsRune(input, markerK) && !strings.ContainsRune(input, markerS) {
		return p.js, utf16Runes(normalizeLegacyIgnoreCaseInput(input, markerK, markerS)), nil
	}
	source := translateECMAScriptPattern(normalizeLegacyIgnoreCaseSource(p.legacySource, markerK, markerS), strings.ContainsRune(p.flags, 'm'))
	js, err := regexp2.Compile(source, p.options)
	if err != nil {
		return nil, nil, err
	}
	js.MatchTimeout = p.js.MatchTimeout
	return js, utf16Runes(normalizeLegacyIgnoreCaseInput(input, markerK, markerS)), nil
}

func splitLiteral(literal string) (string, string, error) {
	if len(literal) < 2 || literal[0] != '/' {
		return "", "", &CompileError{Code: "S0302", Message: "invalid regular expression literal"}
	}
	end := -1
	depth := 0
	for i := 1; i < len(literal); i++ {
		if literal[i] == '/' && depth == 0 && delimiterUnescaped(literal, i) {
			end = i
			break
		}
		if literal[i-1] != '\\' {
			switch literal[i] {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth--
			}
		}
	}
	if end < 0 {
		return "", "", &CompileError{Code: "S0302", Message: "unterminated regular expression literal"}
	}
	return literal[1:end], literal[end+1:], nil
}

func delimiterUnescaped(literal string, position int) bool {
	backslashes := 0
	for index := position - 1; index >= 0 && literal[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 0
}

func re2Compatible(source, flags string) bool {
	// Keep the fast path deliberately narrow. Go and ECMAScript differ for
	// anchors, dot, character classes, escapes, case folding, line boundaries,
	// and UTF-16 handling. Literal ASCII patterns with grouping, alternation,
	// and quantifiers have the same observable matching behavior.
	if flags != "" {
		return false
	}
	if strings.Contains(source, "(?") {
		return false
	}
	for _, char := range source {
		if char > 0x7f || strings.ContainsRune(`\\.[]^$`, char) {
			return false
		}
	}
	return true
}

// asciiRE2IgnoreCaseCompatible identifies a deliberately narrow subset where
// Go's RE2 case folding is equivalent to ECMAScript for ASCII input. Unicode
// folds such as Kelvin sign and long s are excluded by the input gate in
// MatchStringStatic; escaped syntax, anchors, dot, and line controls remain
// on regexp2 because their cross-engine behavior is not proven here.
func asciiRE2IgnoreCaseCompatible(source, flags string) bool {
	if flags != "i" || source == "" || strings.Contains(source, "(?") {
		return false
	}
	inClass := false
	for _, char := range source {
		if char > 0x7f || char < 0x20 || char == 0x7f ||
			strings.ContainsRune(`\\`, char) || (!inClass && strings.ContainsRune(`.^$`, char)) {
			return false
		}
		switch char {
		case '[':
			if inClass {
				return false
			}
			inClass = true
		case ']':
			if !inClass {
				return false
			}
			inClass = false
		case '^':
			// Anchor behavior differs across engines. Keep negated classes
			// conservative; common ASCII ranges remain covered.
			return false
		}
	}
	return !inClass
}

func (p Pattern) MatchString(input string) (bool, error) {
	if p.re2 != nil {
		return p.re2.MatchString(input), nil
	}
	engine, runes, err := p.fallbackEngine(input)
	if err != nil {
		return false, err
	}
	match, err := engine.FindRunesMatch(runes)
	return match != nil, err
}

// MatchStringStatic is the bounded, context-free matcher used by immutable
// decoded plans. RE2 patterns can skip the context-bound wrapper entirely;
// ECMAScript fallback patterns retain the timeout setup used by the normal
// context-aware matcher. The distinction is safe because static plans are
// admitted only when the public evaluation has no caller context or timeout.
func (p Pattern) MatchStringStatic(input string) (bool, error) {
	if p.asciiRe2 != nil && isASCII(input) {
		return p.asciiRe2.MatchString(input), nil
	}
	if p.re2 != nil {
		return p.re2.MatchString(input), nil
	}
	return p.MatchStringContext(context.Background(), input)
}

func isASCII(input string) bool {
	for index := 0; index < len(input); index++ {
		if input[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// MatchStringContext reports whether input matches. Callers use WithTimeout to
// bound fallback work; context is checked synchronously before and after it.
func (p Pattern) MatchStringContext(ctx context.Context, input string) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	matched, err := p.contextBound().MatchString(input)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return false, contextErr
		}
		return false, err
	}
	return matched, contextError(ctx)
}

func (p Pattern) contextBound() Pattern {
	if p.re2 != nil {
		return p
	}
	timeout := contextFallbackTimeout
	// Preserve a caller's finite timeout; regexp2's default is effectively
	// unbounded and must still receive the package's context-safe bound.
	if p.js != nil && p.js != p.contextJS && p.js.MatchTimeout > 0 && p.js.MatchTimeout != regexp2.DefaultMatchTimeout {
		timeout = p.js.MatchTimeout
	}
	return p.WithTimeout(timeout)
}

func (p Pattern) WithTimeout(timeout time.Duration) Pattern {
	if p.re2 != nil || timeout <= 0 {
		return p
	}
	if timeout == contextFallbackTimeout && p.contextJS != nil {
		p.js = p.contextJS
		return p
	}
	// MatchTimeout is the only mutable setting on regexp2. When this pattern
	// already carries the requested timeout, returning it avoids recompiling
	// the same fallback engine. Callers receive a value copy, so the cached
	// engine remains safe to share across evaluations.
	if p.js != nil && p.js.MatchTimeout == timeout {
		return p
	}
	js, err := regexp2.Compile(p.source, p.options)
	if err != nil {
		return p
	}
	js.MatchTimeout = timeout
	p.js = js
	return p
}

func (p Pattern) FindStringSubmatchIndex(input string) ([]int, error) {
	matches, err := p.FindAllStringSubmatchIndex(input, 1)
	if err != nil || len(matches) == 0 {
		return nil, err
	}
	return matches[0], nil
}

func (p Pattern) FindAllStringSubmatchIndex(input string, limit int) ([][]int, error) {
	unitMatches, err := p.FindAllStringSubmatchUTF16Index(input, limit)
	if err != nil {
		return nil, err
	}
	byteOffsets := utf16ByteOffsets(input)
	result := make([][]int, 0, len(unitMatches))
	for _, match := range unitMatches {
		indexes := make([]int, 0, len(match))
		for index := 0; index+1 < len(match); index += 2 {
			if match[index] < 0 || match[index+1] < 0 {
				indexes = append(indexes, -1, -1)
				continue
			}
			start, end, offsetErr := representableByteSpan(byteOffsets, match[index], match[index+1])
			if offsetErr != nil {
				return nil, offsetErr
			}
			indexes = append(indexes, start, end)
		}
		result = append(result, indexes)
	}
	return result, nil
}

// FindAllStringSubmatchUTF16Index returns ECMAScript UTF-16 code-unit spans.
// These offsets can represent lone-surrogate matches without constructing an
// invalid Go string.
func (p Pattern) FindAllStringSubmatchUTF16Index(input string, limit int) ([][]int, error) {
	if p.re2 != nil {
		matches := p.re2.FindAllStringSubmatchIndex(input, limit)
		for _, indexes := range matches {
			for index, offset := range indexes {
				if offset >= 0 {
					indexes[index] = UTF16Index(input, offset)
				}
			}
		}
		return matches, nil
	}
	result := make([][]int, 0)
	engine, matchRunes, err := p.fallbackEngine(input)
	if err != nil {
		return nil, err
	}
	match, err := engine.FindRunesMatch(matchRunes)
	for match != nil && (limit < 0 || len(result) < limit) {
		if err != nil {
			return nil, err
		}
		groups := match.Groups()
		indexes := make([]int, 0, len(groups)*2)
		for _, group := range groups {
			if len(group.Captures) == 0 {
				indexes = append(indexes, -1, -1)
				continue
			}
			indexes = append(indexes, group.Index, group.Index+group.Length)
		}
		result = append(result, indexes)
		nextStart := match.Index + match.Length
		if match.Length == 0 {
			nextStart++
		}
		if nextStart > len(matchRunes) {
			break
		}
		match, err = engine.FindRunesMatchStartingAt(matchRunes, nextStart)
	}
	return result, err
}

func (p Pattern) FindAllStringSubmatchIndexContext(ctx context.Context, input string, limit int) ([][]int, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	matches, err := p.contextBound().FindAllStringSubmatchIndex(input, limit)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	return matches, contextError(ctx)
}

// FindAllStringSubmatchUTF16IndexContext is the cancellable UTF-16 offset
// variant used by the evaluator.
func (p Pattern) FindAllStringSubmatchUTF16IndexContext(ctx context.Context, input string, limit int) ([][]int, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	matches, err := p.contextBound().FindAllStringSubmatchUTF16Index(input, limit)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	return matches, contextError(ctx)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// IsTimeout reports regexp2's stable match-timeout failure without treating
// representation or syntax failures as resource exhaustion.
func IsTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "match timeout after")
}

// UTF16RepresentationError reports a match result containing a lone
// surrogate. Go strings and encoding/json cannot preserve that ECMAScript
// value without replacement or invalid UTF-8.
type UTF16RepresentationError struct {
	Start int
	End   int
}

func (e *UTF16RepresentationError) Error() string {
	return fmt.Sprintf("regular expression result spans unpaired UTF-16 surrogate units %d:%d, which cannot be represented as a Go string", e.Start, e.End)

}

func utf16Runes(input string) []rune {
	units := UTF16Units(input)
	result := make([]rune, len(units))
	for index, unit := range units {
		result[index] = rune(unit)
	}
	return result
}

// UTF16Units encodes a valid Go string as ECMAScript string code units.
func UTF16Units(input string) []uint16 {
	return utf16.Encode([]rune(input))
}

// UTF16String decodes code units only when they form valid scalar values.
func UTF16String(units []uint16) (string, error) {
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+1 >= len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return "", &UTF16RepresentationError{Start: index, End: index + 1}
			}
			index++
		case unit >= 0xdc00 && unit <= 0xdfff:
			return "", &UTF16RepresentationError{Start: index, End: index + 1}
		}
	}
	return string(utf16.Decode(units)), nil
}

// UTF16Slice extracts a code-unit range when it is representable as a valid
// Go string.
func UTF16Slice(input string, start, end int) (string, error) {
	units := UTF16Units(input)
	if start < 0 || end < start || end > len(units) {
		return "", fmt.Errorf("invalid UTF-16 string range %d:%d", start, end)
	}
	return UTF16String(units[start:end])
}

func utf16Surrogates(char rune) (rune, rune) {
	value := char - 0x10000
	return 0xd800 + value>>10, 0xdc00 + value&0x3ff
}

func utf16ByteOffsets(input string) []int {
	offsets := make([]int, 1, UTF16Index(input, len(input))+1)
	for byteIndex, char := range input {
		if char > 0xffff {
			offsets = append(offsets, -1)
		}
		_, size := utf8.DecodeRuneInString(input[byteIndex:])
		offsets = append(offsets, byteIndex+size)
	}
	return offsets
}

func representableByteSpan(offsets []int, start, end int) (int, int, error) {
	if start < 0 || end < start || start >= len(offsets) || end >= len(offsets) {
		return 0, 0, fmt.Errorf("regular expression returned invalid UTF-16 offsets %d:%d", start, end)
	}
	if start == end {
		if offsets[start] >= 0 {
			return offsets[start], offsets[start], nil
		}
		for index := start - 1; index >= 0; index-- {
			if offsets[index] >= 0 {
				return offsets[index], offsets[index], nil
			}
		}
	}
	if offsets[start] < 0 || offsets[end] < 0 {
		return 0, 0, &UTF16RepresentationError{Start: start, End: end}
	}
	return offsets[start], offsets[end], nil
}

// UTF16Index converts a UTF-8 byte offset to the JavaScript string index used
// by JSONata match objects.
func UTF16Index(input string, byteIndex int) int {
	if byteIndex <= 0 {
		return 0
	}
	if byteIndex > len(input) {
		byteIndex = len(input)
	}
	units := 0
	for offset := 0; offset < byteIndex; {
		r, size := utf8.DecodeRuneInString(input[offset:])
		if r > 0xffff {
			units += 2
		} else {
			units++
		}
		offset += size
	}
	return units
}

// ByteIndex converts a JavaScript UTF-16 string index to a UTF-8 byte offset.
// Indexes inside a surrogate pair resolve to the start of that code point.
func ByteIndex(input string, utf16Index int) int {
	index, _ := ByteIndexExact(input, utf16Index)
	return index
}

// ByteIndexExact converts a UTF-16 index and reports whether it lies on a Go
// string boundary. Indexes inside a surrogate pair return its starting byte
// with exact set to false.
func ByteIndexExact(input string, utf16Index int) (index int, exact bool) {
	if utf16Index <= 0 {
		return 0, true
	}
	units := 0
	for offset, r := range input {
		width := 1
		if r > 0xffff {
			width = 2
		}
		if units+width > utf16Index {
			return offset, false
		}
		units += width
		if units == utf16Index {
			_, size := utf8.DecodeRuneInString(input[offset:])
			return offset + size, true
		}
	}
	return len(input), utf16Index == units
}
