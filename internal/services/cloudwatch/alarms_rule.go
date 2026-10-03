package cloudwatch

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"stackd/internal/awswire"
)

// alarmRuleNode keeps occurrences in quorum groups: dependency identity is
// deduplicated separately, not substituted for the expression's operands.
type alarmRuleNode struct {
	op          string
	left, right *alarmRuleNode
	name, state string
	names       []string
	minimum     int
	negated     bool
}

// evaluate retains only operands sufficient to establish the result. The shared
// buffer avoids allocating a separate witness list at every expression node.
func (n *alarmRuleNode) evaluate(states map[string]string, witnesses []string) (bool, []string) {
	switch n.op {
	case "TRUE":
		return true, witnesses
	case "FALSE":
		return false, witnesses
	case "NOT":
		result, witnesses := n.left.evaluate(states, witnesses)
		return !result, witnesses
	case "AND", "OR":
		start := len(witnesses)
		left, witnesses := n.left.evaluate(states, witnesses)
		if n.op == "AND" && !left || n.op == "OR" && left {
			return left, witnesses
		}
		leftEnd := len(witnesses)
		right, witnesses := n.right.evaluate(states, witnesses)
		if right != left {
			// The right operand alone determines false AND / true OR.
			witnesses = append(witnesses[:start], witnesses[leftEnd:]...)
		}
		return right, witnesses
	case "STATE":
		return states[n.name] == n.state, append(witnesses, n.name)
	case "AT_LEAST":
		matched := 0
		for _, name := range n.names {
			if (states[name] == n.state) != n.negated {
				matched++
			}
		}
		result, needed := matched >= n.minimum, n.minimum
		if !result {
			needed = len(n.names) - n.minimum + 1
		}
		for _, name := range n.names {
			if ((states[name] == n.state) != n.negated) != result {
				continue
			}
			witnesses = append(witnesses, name)
			needed--
			if needed == 0 {
				break
			}
		}
		return result, witnesses
	}
	return false, witnesses
}

type alarmRuleParser struct {
	scope    Scope
	text     string
	at       int
	elements int
	children map[string]struct{}
	err      *awswire.Error
}

func compileAlarmRule(scope Scope, rule string) ([]string, *awswire.Error) {
	_, children, failure := parseAlarmRule(scope, rule)
	return children, failure
}

func parseAlarmRule(scope Scope, rule string) (*alarmRuleNode, []string, *awswire.Error) {
	p := alarmRuleParser{scope: scope, text: rule, children: map[string]struct{}{}}
	node := p.expression(1)
	if p.peek() != "" {
		p.fail("unexpected trailing token")
	}
	if p.err != nil {
		return nil, nil, p.err
	}
	children := make([]string, 0, len(p.children))
	for name := range p.children {
		children = append(children, name)
	}
	slices.Sort(children)
	return node, children, nil
}

func (p *alarmRuleParser) fail(message string) {
	if p.err == nil {
		p.err = alarmInvalid(fmt.Sprintf("Error in AlarmRule at character %d: %s", p.at, message))
	}
}

func (p *alarmRuleParser) element() {
	p.elements++
	if p.elements > 500 {
		p.fail("the rule exceeds 500 elements")
	}
}

func (p *alarmRuleParser) whitespace() {
	for p.at < len(p.text) {
		r, size := utf8.DecodeRuneInString(p.text[p.at:])
		if !unicode.IsSpace(r) {
			break
		}
		p.at += size
	}
}

// Tokens retain their quoted spelling until the alarm-reference boundary.
func (p *alarmRuleParser) token() string {
	p.whitespace()
	start := p.at
	if start == len(p.text) {
		return ""
	}
	if strings.ContainsRune("(),", rune(p.text[p.at])) {
		p.at++
		return p.text[start:p.at]
	}
	if p.text[p.at] == '"' {
		p.at++
		for p.at < len(p.text) {
			c := p.text[p.at]
			p.at++
			if c == '\\' && p.at < len(p.text) {
				p.at++
			} else if c == '"' {
				return p.text[start:p.at]
			}
		}
		p.fail("unterminated quoted alarm reference")
		return p.text[start:p.at]
	}
	for p.at < len(p.text) {
		r, size := utf8.DecodeRuneInString(p.text[p.at:])
		if unicode.IsSpace(r) || strings.ContainsRune("(),", r) {
			break
		}
		p.at += size
	}
	return p.text[start:p.at]
}

func (p *alarmRuleParser) peek() string {
	at := p.at
	token := p.token()
	p.at = at
	return token
}

func (p *alarmRuleParser) expect(expected string) {
	if p.token() != expected {
		p.fail("expected " + expected)
	}
}

func (p *alarmRuleParser) expression(minimum int) *alarmRuleNode {
	left := p.unary()
	for p.err == nil {
		op := p.peek()
		precedence := 0
		switch op {
		case "OR":
			precedence = 1
		case "AND":
			precedence = 2
		}
		if precedence < minimum {
			break
		}
		p.token()
		left = &alarmRuleNode{op: op, left: left, right: p.expression(precedence + 1)}
	}
	return left
}

func (p *alarmRuleParser) unary() *alarmRuleNode {
	if p.err != nil {
		return nil
	}
	token := p.token()
	switch token {
	case "NOT":
		return &alarmRuleNode{op: token, left: p.unary()}
	case "TRUE", "FALSE":
		p.element()
		return &alarmRuleNode{op: token}
	case "(":
		p.element()
		node := p.expression(1)
		p.expect(")")
		p.element()
		return node
	case "ALARM", "OK", "INSUFFICIENT_DATA":
		p.expect("(")
		name := p.reference()
		p.expect(")")
		return &alarmRuleNode{op: "STATE", name: name, state: token}
	case "AT_LEAST":
		return p.quorum()
	default:
		p.fail("expected a state function, TRUE, FALSE, NOT, AT_LEAST or a grouped expression")
		return nil
	}
}

func (p *alarmRuleParser) reference() string {
	token := p.token()
	if token == "" || token == "(" || token == ")" || token == "," {
		p.fail("expected an alarm reference")
		return ""
	}
	if strings.HasPrefix(token, "\"") {
		var decoded string
		if err := json.Unmarshal([]byte(token), &decoded); err != nil {
			p.fail("invalid quoted alarm reference")
			return ""
		}
		token = decoded
	}
	key, failure := alarmReference(p.scope, token)
	if failure != nil {
		p.err = failure
		return ""
	}
	p.element()
	p.children[key.Name] = struct{}{}
	if len(p.children) > 100 {
		p.fail("the rule references more than 100 alarms")
	}
	return key.Name
}

func (p *alarmRuleParser) quorum() *alarmRuleNode {
	p.expect("(")
	text := p.token()
	percent := strings.HasSuffix(text, "%")
	text = strings.TrimSuffix(text, "%")
	for _, c := range text {
		if c < '0' || c > '9' {
			p.fail("AT_LEAST requires an integer count or integer percentage")
		}
	}
	minimum, err := strconv.Atoi(text)
	if err != nil || minimum < 1 || percent && minimum > 100 {
		p.fail("AT_LEAST requires a positive count or percentage from 1 through 100")
	}
	p.expect(",")
	node := &alarmRuleNode{op: "AT_LEAST", minimum: minimum}
	node.state = p.token()
	if node.state == "NOT" {
		node.negated = true
		node.state = p.token()
	}
	if node.state != "ALARM" && node.state != "OK" && node.state != "INSUFFICIENT_DATA" {
		p.fail("AT_LEAST requires an alarm state condition")
	}
	p.expect(",")
	p.expect("(")
	for p.err == nil {
		node.names = append(node.names, p.reference())
		if p.peek() != "," {
			break
		}
		p.token()
	}
	p.expect(")")
	p.expect(")")
	if percent {
		node.minimum = (minimum*len(node.names) + 99) / 100
	} else if minimum > len(node.names) {
		p.fail("AT_LEAST count exceeds the number of alarm references")
	}
	return node
}
