package policy

import (
	"context"
	"encoding/binary"
	"slices"
)

// permissionGlob is a small NFA for the resource selectors used in permission
// reports. Evaluating the product finds an allowed resource even when an Allow
// overlaps several Deny patterns; it does not guess example resource names.
type permissionGlob struct {
	tokens     []patternToken
	crossColon []bool
}

func compilePermissionGlob(pattern string, template bool) permissionGlob {
	var tokens []patternToken
	var crosses []bool
	segment := 0
	input := patternTokens(pattern, false)
	for index := 0; index < len(input); index++ {
		token := input[index]
		if template && token.char == '$' && index+1 < len(input) && input[index+1].char == '{' {
			if end := slices.IndexFunc(input[index+2:], func(t patternToken) bool { return t.char == '}' }); end >= 0 {
				tokens = append(tokens, patternToken{kind: starPattern})
				crosses = append(crosses, segment >= 5)
				index += end + 2
				continue
			}
		}
		tokens = append(tokens, token)
		crosses = append(crosses, segment >= 5 || token.kind == starPattern && (index+1 == len(input) || input[index+1].char == ':'))
		if token.char == ':' {
			segment++
		}
	}
	return permissionGlob{tokens, crosses}
}

func (g permissionGlob) closure(states []int) []int {
	seen := make([]bool, len(g.tokens)+1)
	for _, i := range states {
		seen[i] = true
		for i < len(g.tokens) && g.tokens[i].kind == starPattern {
			i++
			seen[i] = true
		}
	}
	result := make([]int, 0, len(states)+1)
	for i, present := range seen {
		if present {
			result = append(result, i)
		}
	}
	return result
}
func (g permissionGlob) step(states []int, r uint16) []int {
	next := make([]int, 0, len(states))
	for _, i := range states {
		if i == len(g.tokens) {
			continue
		}
		token := g.tokens[i]
		switch token.kind {
		case literalPattern:
			if token.char == r {
				next = append(next, i+1)
			}
		case anyPattern:
			if g.crossColon[i] || r != ':' {
				next = append(next, i+1)
			}
		case starPattern:
			if g.crossColon[i] || r != ':' {
				next = append(next, i)
			}
		}
	}
	return g.closure(next)
}
func permissionStateKey(states [][]int) string {
	var key []byte
	for _, state := range states {
		for _, i := range state {
			key = binary.AppendUvarint(key, uint64(i+1))
		}
		key = append(key, 0)
	}
	return string(key)
}

type permissionResourceSelector struct {
	patterns []int
	negate   bool
	effect   Decision
	level    int
}

func potentialResource(ctx context.Context, templates []string, levels [][]permissionStatement, maxBytes int) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	hasDeny := false
	allLevelsUnrestricted := true
	for _, statements := range levels {
		hasAllow, allResources := false, false
		for _, statement := range statements {
			if statement.effect == ExplicitDeny {
				hasDeny = true
				if !statement.notResource && slices.Contains(statement.resources, "*") {
					return false, nil
				}
			} else {
				hasAllow = true
				allResources = allResources || !statement.notResource && slices.Contains(statement.resources, "*")
			}
		}
		if !hasAllow {
			return false, nil
		}
		allLevelsUnrestricted = allLevelsUnrestricted && allResources
	}
	if allLevelsUnrestricted && !hasDeny && maxBytes == 0 {
		return true, nil
	}
	// Resource types are alternatives. Distribute the existential resource
	// search over each template instead of taking a product of unrelated ARN
	// languages, which makes services with many ARN forms explode in size.
	if len(templates) == 0 {
		return potentialResourceTemplate(ctx, "", levels, maxBytes)
	}
	for _, template := range templates {
		allowed, err := potentialResourceTemplate(ctx, template, levels, maxBytes)
		if err != nil || allowed {
			return allowed, err
		}
	}
	return false, nil
}

func potentialResourceTemplate(ctx context.Context, template string, levels [][]permissionStatement, maxBytes int) (bool, error) {
	var globs []permissionGlob
	indexes := make(map[string]int)
	add := func(pattern string, template bool) int {
		key := pattern
		if template {
			key = "template\x00" + pattern
		}
		if i, exists := indexes[key]; exists {
			return i
		}
		i := len(globs)
		indexes[key] = i
		globs = append(globs, compilePermissionGlob(pattern, template))
		return i
	}
	universe := add(template, true)
	if template == "" {
		// An API without resource-level permissions uses the literal '*'.
		globs[universe] = permissionGlob{tokens: []patternToken{{kind: literalPattern, char: '*'}}, crossColon: []bool{false}}
	}
	var selectors []permissionResourceSelector
	for level, statements := range levels {
		for _, statement := range statements {
			selector := permissionResourceSelector{negate: statement.notResource, effect: statement.effect, level: level}
			for _, pattern := range statement.resources {
				selector.patterns = append(selector.patterns, add(pattern, false))
			}
			selectors = append(selectors, selector)
		}
	}
	alphabet := map[uint16]bool{':': true, '*': true}
	for _, g := range globs {
		for _, token := range g.tokens {
			if token.kind == literalPattern {
				alphabet[token.char] = true
			}
		}
	}
	// Characters absent from the literal alphabet have identical glob
	// transitions. Bounded searches also distinguish UTF-8 byte costs and
	// surrogate halves, so every valid Unicode equivalence class is represented.
	if maxBytes == 0 {
		other := uint16(1)
		for alphabet[other] {
			other++
		}
		alphabet[other] = true
	} else {
		for _, interval := range [][2]int{{0, 0x7f}, {0x80, 0x7ff}, {0x800, 0xd7ff}, {0xd800, 0xdbff}, {0xdc00, 0xdfff}, {0xe000, 0xffff}} {
			for other := interval[0]; other <= interval[1]; other++ {
				if !alphabet[uint16(other)] {
					alphabet[uint16(other)] = true
					break
				}
			}
		}
	}
	letters := make([]uint16, 0, len(alphabet))
	for r := range alphabet {
		letters = append(letters, r)
	}
	slices.Sort(letters)
	initial := make([][]int, len(globs))
	for i, g := range globs {
		initial[i] = g.closure([]int{0})
	}
	type searchState struct {
		globs         [][]int
		bytes         int
		highSurrogate bool
	}
	stateKey := func(state searchState) string {
		key := permissionStateKey(state.globs)
		if maxBytes > 0 {
			if state.highSurrogate {
				return key + "1"
			}
			return key + "0"
		}
		return key
	}
	start := searchState{globs: initial}
	queue := []searchState{start}
	// For a given product state, a shorter valid prefix dominates every
	// longer prefix. Revisit only when a lower UTF-8 cost is discovered.
	visited := map[string]int{stateKey(start): 0}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		current := queue[0]
		queue = queue[1:]
		states := current.globs
		accepted := make([]bool, len(globs))
		for i, state := range states {
			accepted[i] = slices.Contains(state, len(globs[i].tokens))
		}
		inUniverse := accepted[universe]
		liveUniverse := len(states[universe]) > 0
		if inUniverse && !current.highSurrogate {
			allowed := make([]bool, len(levels))
			denied := false
			for _, selector := range selectors {
				matches := false
				for _, i := range selector.patterns {
					matches = matches || accepted[i]
				}
				if matches == selector.negate {
					continue
				}
				if selector.effect == ExplicitDeny {
					denied = true
					break
				} else {
					allowed[selector.level] = true
				}
			}
			if !denied && !slices.Contains(allowed, false) {
				return true, nil
			}
		}
		if !liveUniverse {
			continue
		}
		for _, r := range letters {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			cost, pending := 0, false
			if maxBytes > 0 {
				var valid bool
				cost, pending, valid = permissionUTF8Step(r, current.highSurrogate)
				if !valid || cost > maxBytes-current.bytes {
					continue
				}
			}
			next := make([][]int, len(globs))
			for i, g := range globs {
				next[i] = g.step(states[i], r)
			}
			candidate := searchState{globs: next, bytes: current.bytes + cost, highSurrogate: pending}
			key := stateKey(candidate)
			if previous, exists := visited[key]; !exists || candidate.bytes < previous {
				visited[key] = candidate.bytes
				queue = append(queue, candidate)
			}
		}
	}
	return false, nil
}

// IAM globs consume UTF-16 units, while consumers bound valid UTF-8 bytes. Charge
// all four bytes when entering a surrogate pair; only its low half may follow.
func permissionUTF8Step(unit uint16, highSurrogate bool) (bytes int, pending, valid bool) {
	if highSurrogate {
		return 0, false, unit >= 0xdc00 && unit <= 0xdfff
	}
	switch {
	case unit <= 0x7f:
		return 1, false, true
	case unit <= 0x7ff:
		return 2, false, true
	case unit >= 0xd800 && unit <= 0xdbff:
		return 4, true, true
	case unit >= 0xdc00 && unit <= 0xdfff:
		return 0, false, false
	default:
		return 3, false, true
	}
}
