package inputtransform

import (
	"fmt"
	"strconv"
	"strings"
)

type pathStep struct {
	field             string
	index             int
	indexed, wildcard bool
}
type path []pathStep

func compilePath(source string) (path, error) {
	if source == "" || source[0] != '$' {
		return nil, fmt.Errorf("input path must start with $")
	}
	steps := path{}
	for i := 1; i < len(source); {
		switch source[i] {
		case '.':
			i++
			start := i
			for i < len(source) && source[i] != '.' && source[i] != '[' {
				i++
			}
			name := source[start:i]
			if name == "" {
				return nil, fmt.Errorf("input path contains an empty field")
			}
			for _, r := range name {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '/') {
					return nil, fmt.Errorf("invalid JSON path field %q", name)
				}
			}
			steps = append(steps, pathStep{field: name})
		case '[':
			end := strings.IndexByte(source[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("unterminated JSON path index")
			}
			index := source[i+1 : i+end]
			step := pathStep{indexed: true, wildcard: index == "*"}
			if !step.wildcard {
				if index == "" || strings.Trim(index, "0123456789") != "" {
					return nil, fmt.Errorf("invalid JSON path array index")
				}
				n, err := strconv.Atoi(index)
				if err != nil {
					return nil, fmt.Errorf("invalid JSON path array index")
				}
				step.index = n
			}
			steps = append(steps, step)
			i += end + 1
		default:
			return nil, fmt.Errorf("invalid JSON path at byte %d", i)
		}
	}
	return steps, nil
}

func (p path) selectValue(root *value) *value {
	if p == nil {
		return nil
	}
	values := []*value{root}
	multiple := false
	for _, step := range p {
		var next []*value
		for _, v := range values {
			switch {
			case step.wildcard:
				multiple = true
				if v.kind == '[' {
					next = append(next, v.items...)
				}
			case step.indexed:
				if v.kind == '[' && step.index < len(v.items) {
					next = append(next, v.items[step.index])
				}
			default:
				if v.kind == '{' {
					if child := v.field(step.field); child != nil {
						next = append(next, child)
					}
				}
			}
		}
		values = next
	}
	if multiple {
		return arrayValue(values)
	}
	if len(values) == 0 {
		return nil
	}
	return values[0]
}
