package eventpattern

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Native admission rejects more than ten simultaneously reachable wildcard
// prefixes. This is the weighted byte-machine criterion described by AWS's
// event-ruler MachineComplexityEvaluator, not a count of wildcard characters.
const wildcardComplexityLimit = 10

type complexityTerm struct {
	identity  string
	wildcards []string
	absent    bool
}

func describeComplexity(v value) complexityTerm {
	t := complexityTerm{identity: complexityIdentity(v)}
	if v.kind != objectValue {
		return t
	}
	op := v.members[0]
	if op.name == "exists" {
		t.absent = op.value.text == "false"
	}
	if op.name == "numeric" && len(op.value.items) == 2 && op.value.items[0].text == "=" {
		t.identity = complexityIdentity(op.value.items[1])
	}
	if op.name == "cidr" {
		// compileTerm already validated this value with the same bounds
		// constructor used by the matcher.
		lower, upper, _ := cidrBounds(op.value.text)
		t.identity = "cidr:" + lower + ":" + upper
	}
	if op.name == "anything-but" {
		operand, kind := op.value, "anything-but"
		if operand.kind == objectValue {
			kind += ":" + operand.members[0].name
			operand = operand.members[0].value
		}
		items := operand.items
		if operand.kind != arrayValue {
			items = []value{operand}
		}
		parts := make([]string, len(items))
		for i, item := range items {
			parts[i] = complexityIdentity(item)
		}
		slices.Sort(parts)
		t.identity = kind + ":[" + strings.Join(slices.Compact(parts), ",") + "]"
	}
	if op.name == "wildcard" {
		t.wildcards = []string{op.value.text}
	} else if op.name == "anything-but" && op.value.kind == objectValue && op.value.members[0].name == "wildcard" {
		operand := op.value.members[0].value
		if operand.kind == stringValue {
			t.wildcards = []string{operand.text}
		} else {
			for _, item := range operand.items {
				t.wildcards = append(t.wildcards, item.text)
			}
			slices.Sort(t.wildcards)
			t.wildcards = slices.Compact(t.wildcards)
		}
	}
	return t
}

// Identities group equal preceding field alternatives into the same next name
// state. A negated wildcard list is one pattern with several byte paths.
func complexityIdentity(v value) string {
	switch v.kind {
	case stringValue:
		return strconv.Quote(v.text)
	case numberValue:
		if n, ok := comparable(v.text); ok {
			return strconv.FormatFloat(n, 'g', -1, 64)
		}
		return v.text
	case boolValue:
		return v.text
	case nullValue:
		return "null"
	case arrayValue:
		parts := make([]string, len(v.items))
		for i, item := range v.items {
			parts[i] = complexityIdentity(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	default:
		parts := make([]string, len(v.members))
		for i, member := range v.members {
			parts[i] = strconv.Quote(member.name) + ":" + complexityIdentity(member.value)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
}

type complexityName struct{ fields map[string]*complexityField }
type complexityField struct {
	terms []complexityTerm
	next  map[string]*complexityName
	value map[*complexityName]bool
}

func checkComplexity(clauses []clause) error {
	hasWildcard := false
	for _, clause := range clauses {
		for _, field := range clause {
			for _, term := range field.admission {
				hasWildcard = hasWildcard || len(term.wildcards) != 0
			}
		}
	}
	if !hasWildcard {
		return nil
	}
	root := &complexityName{}
	for _, clause := range clauses {
		fields := slices.Clone(clause)
		slices.SortFunc(fields, func(a, b field) int { return strings.Compare(a.path, b.path) })
		states := map[*complexityName]bool{root: true}
		for _, field := range fields {
			next := map[*complexityName]bool{}
			for state := range states {
				if state.fields == nil {
					state.fields = map[string]*complexityField{}
				}
				machine := state.fields[field.path]
				if machine == nil {
					machine = &complexityField{next: map[string]*complexityName{}, value: map[*complexityName]bool{}}
					state.fields[field.path] = machine
				}
				var last *complexityName
				for _, term := range field.admission {
					machine.terms = append(machine.terms, term)
					if old := machine.next[term.identity]; old != nil {
						last = old
					} else {
						if last == nil {
							last = &complexityName{}
						}
						machine.next[term.identity] = last
					}
					next[last] = true
					if !term.absent {
						machine.value[last] = true
					}
				}
			}
			states = next
		}
	}
	seen := map[*complexityName]bool{}
	pending := []*complexityName{root}
	for len(pending) != 0 {
		state := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[state] {
			continue
		}
		seen[state] = true
		for _, machine := range state.fields {
			if wildcardComplexity(machine.terms) > wildcardComplexityLimit {
				return fmt.Errorf("rule is too complex - try using fewer wildcard characters or fewer repeating character sequences after a wildcard character")
			}
			// Native AWS retains event-ruler's pre-2.1 behavior: machines
			// reachable only through exists:false edges are not evaluated.
			for next := range machine.value {
				pending = append(pending, next)
			}
		}
	}
	return nil
}

type complexityByte struct {
	literal map[byte][]int
	any     []int
	weight  map[string]bool
	prefix  map[byte]int
	star    int
}

func wildcardComplexity(terms []complexityTerm) int {
	states := []complexityByte{{}}
	// Determinate prefixes and their first wildcard transition share storage.
	// Literal paths after a wildcard remain distinct, including repeated
	// wildcard alternatives, because wildcard/empty transitions converge there.
	matches := map[string]int{}
	alphabet := map[byte]bool{}
	for _, term := range terms {
		for _, pattern := range term.wildcards {
			tokens := wildcardBytes(pattern)
			current, previous := 0, -1
			determinate := true
			for i, token := range tokens {
				next := 0
				terminal := i == len(tokens)-1
				if terminal {
					next = matches[term.identity]
				} else if token == 256 {
					if determinate {
						next = states[current].star
						if next == 0 {
							states[current].star = len(states)
						}
					}
					determinate = false
				} else if determinate {
					next = states[current].prefix[byte(token)]
				}
				created := next == 0
				if created {
					next = len(states)
					states = append(states, complexityByte{})
					if terminal {
						matches[term.identity] = next
					} else if determinate {
						if states[current].prefix == nil {
							states[current].prefix = map[byte]int{}
						}
						states[current].prefix[byte(token)] = next
					}
				}
				if token == 256 {
					if len(states[next].any) == 0 {
						states[current].any = append(states[current].any, next)
						states[next].any = []int{next}
					}
				} else if terminal || created {
					b := byte(token)
					alphabet[b] = true
					if states[current].literal == nil {
						states[current].literal = map[byte][]int{}
					}
					states[current].literal[b] = append(states[current].literal[b], next)
					if i > 0 && tokens[i-1] == 256 {
						if states[previous].literal == nil {
							states[previous].literal = map[byte][]int{}
						}
						states[previous].literal[b] = append(states[previous].literal[b], next)
					}
				}
				if states[next].weight == nil {
					states[next].weight = map[string]bool{}
				}
				states[next].weight[term.identity] = true
				previous, current = current, next
			}
		}
	}
	if len(states) == 1 {
		return 0
	}
	bytes := []int{256} // One representative for bytes without literal transitions.
	for b := range alphabet {
		bytes = append(bytes, int(b))
	}
	pending := [][]int{{0}}
	seen := map[string]bool{}
	maximum := 0
	for len(pending) > 0 {
		active := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for _, b := range bytes {
			nextSet := map[int]bool{}
			for _, id := range active {
				for _, next := range states[id].any {
					nextSet[next] = true
				}
				if b != 256 {
					for _, next := range states[id].literal[byte(b)] {
						nextSet[next] = true
					}
				}
			}
			if len(nextSet) == 0 {
				continue
			}
			next := make([]int, 0, len(nextSet))
			complexity := 0
			for id := range nextSet {
				next = append(next, id)
				complexity += len(states[id].weight)
				for _, wildcard := range states[id].any {
					if !nextSet[wildcard] {
						complexity += len(states[wildcard].weight)
					}
				}
			}
			if complexity > wildcardComplexityLimit {
				return complexity
			}
			maximum = max(maximum, complexity)
			slices.Sort(next)
			key := fmt.Sprint(next)
			if !seen[key] {
				seen[key] = true
				pending = append(pending, next)
			}
		}
	}
	return maximum
}

// Grammar validation has already rejected malformed escapes. Event-ruler
// evaluates UTF-8 bytes and includes the string's enclosing quote transitions.
func wildcardBytes(pattern string) []int {
	tokens := []int{'"'}
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			tokens = append(tokens, 256)
		case '\\':
			i++
			tokens = append(tokens, int(pattern[i]))
		default:
			tokens = append(tokens, int(pattern[i]))
		}
	}
	return append(tokens, '"')
}
