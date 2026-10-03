package policy

import (
	"strings"
	"unicode/utf16"
)

type patternKind uint8

const (
	literalPattern patternKind = iota
	starPattern
	anyPattern
)

type patternToken struct {
	kind patternKind
	char uint16
}

func patternTokens(text string, literal bool) []patternToken {
	tokens := make([]patternToken, 0, len(text))
	for _, r := range utf16.Encode([]rune(text)) {
		token := patternToken{kind: literalPattern, char: r}
		if !literal {
			if r == '*' {
				token.kind = starPattern
			}
			if r == '?' {
				token.kind = anyPattern
			}
		}
		tokens = append(tokens, token)
	}
	return tokens
}

// wildcardMatch implements IAM's * and ? patterns. Unlike path.Match, slash,
// brackets, and backslash have no special meaning. A question mark matches one
// UTF-16 unit, so a supplementary character requires two. Dynamic programming bounds
// work by pattern length times input length, avoiding recursive backtracking.
func wildcardMatch(pattern, value string, resource bool) bool {
	return matchPattern(patternTokens(pattern, false), value, resource)
}
func matchPattern(pattern []patternToken, value string, resource bool) bool {
	if len(pattern) == 1 && pattern[0].kind == starPattern {
		return true
	}
	v := utf16.Encode([]rune(value))
	previous := make([]bool, len(v)+1)
	current := make([]bool, len(v)+1)
	previous[0] = true
	segment := 0
	for i, token := range pattern {
		clear(current)
		if token.kind == starPattern {
			current[0] = previous[0]
		}
		trailingStar := token.kind == starPattern && (i+1 == len(pattern) || pattern[i+1].kind == literalPattern && pattern[i+1].char == ':')
		crossColon := !resource || segment >= 5 || trailingStar
		for j, r := range v {
			switch token.kind {
			case starPattern:
				current[j+1] = previous[j+1] || (current[j] && (crossColon || r != ':'))
			case anyPattern:
				current[j+1] = previous[j] && (crossColon || r != ':')
			default:
				current[j+1] = previous[j] && token.char == r
			}
		}
		if token.kind == literalPattern && token.char == ':' {
			segment++
		}
		previous, current = current, previous
	}
	return previous[len(v)]
}
func arnMatch(pattern, value string) bool {
	return matchARNPattern(patternTokens(pattern, false), value)
}
func matchARNPattern(pattern []patternToken, value string) bool {
	if len(pattern) == 1 && pattern[0].kind == starPattern {
		return true
	}
	p := make([][]patternToken, 1, 6)
	for _, token := range pattern {
		if len(p) < 6 && token.kind == literalPattern && token.char == ':' {
			p = append(p, nil)
		} else {
			p[len(p)-1] = append(p[len(p)-1], token)
		}
	}
	v := strings.SplitN(value, ":", 6)
	if len(p) != 6 || len(v) != 6 {
		return false
	}
	for i := range p {
		if !matchPattern(p[i], v[i], false) {
			return false
		}
	}
	return true
}
