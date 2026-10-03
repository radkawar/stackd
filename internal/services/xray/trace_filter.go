package xray

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/xray"
)

type traceFilter struct{ expression traceExpression }
type traceExpression interface {
	evaluate(*traceFilterContext) bool
}
type traceFilterContext struct {
	view   *traceView
	window *traceWindow
	output *api.TraceSummary
	entity *traceEntity
	node   *traceNode
	edge   *traceEdge
	fields map[string]any
}

type traceLogical struct {
	operator    string
	left, right traceExpression
}

func (e traceLogical) evaluate(c *traceFilterContext) bool {
	// Failed branches and negations must not leak matched-service projections.
	var saved api.TraceSummary
	if c.output != nil {
		saved = *c.output
	}
	switch e.operator {
	case "not":
		result := !e.left.evaluate(c)
		if c.output != nil {
			*c.output = saved
		}
		return result
	case "and":
		if e.left.evaluate(c) && e.right.evaluate(c) {
			return true
		}
	case "or":
		if e.left.evaluate(c) {
			return true
		}
		if c.output != nil {
			*c.output = saved
		}
		if e.right.evaluate(c) {
			return true
		}
	}
	if c.output != nil {
		*c.output = saved
	}
	return false
}

type traceTrue struct{}

func (traceTrue) evaluate(*traceFilterContext) bool { return true }

type traceFalse struct{}

func (traceFalse) evaluate(*traceFilterContext) bool { return false }

type traceComparison struct {
	field, operator string
	value           any
}

func (e traceComparison) evaluate(c *traceFilterContext) bool {
	for _, actual := range traceFilterValues(c, e.field) {
		if traceCompare(actual, e.operator, e.value) {
			return true
		}
	}
	return false
}
func traceCompare(actual any, op string, wanted any) bool {
	if op == "" {
		if b, ok := actual.(bool); ok {
			return b
		}
		return actual != nil
	}
	switch a := actual.(type) {
	case bool:
		b, ok := wanted.(bool)
		if !ok {
			if text, isString := wanted.(string); isString && (text == "true" || text == "false") {
				b = text == "true"
				ok = true
			}
		}
		if !ok {
			return false
		}
		if op == "=" {
			return a == b
		}
		if op == "!=" {
			return a != b
		}
	case float64:
		b, ok := wanted.(float64)
		if !ok {
			return false
		}
		switch op {
		case "=":
			return a == b
		case "!=":
			return a != b
		case "<":
			return a < b
		case "<=":
			return a <= b
		case ">":
			return a > b
		case ">=":
			return a >= b
		}
	case string:
		b, ok := wanted.(string)
		if !ok {
			return false
		}
		switch op {
		case "=":
			return a == b
		case "!=":
			return a != b
		case "contains":
			return strings.Contains(a, b)
		case "beginswith":
			return strings.HasPrefix(a, b)
		case "endswith":
			return strings.HasSuffix(a, b)
		}
	}
	return false
}

type traceSelectorID struct{ name, kind, account *string }

func (id traceSelectorID) matches(n *traceNode) bool {
	return (id.name == nil || *id.name == n.identity.name) && (id.kind == nil || *id.kind == n.identity.kind) && (id.account == nil || *id.account == n.identity.account)
}

type traceSelector struct {
	kind                string
	source, destination traceSelectorID
	body                traceExpression
}

func (e traceSelector) evaluate(c *traceFilterContext) bool {
	if e.kind == "service" {
		for _, n := range c.view.nodes {
			if !e.source.matches(n) {
				continue
			}
			entities := n.entities
			if n.client {
				for _, edge := range c.view.edges {
					if edge.source == n {
						entities = append(entities, edge.entity)
					}
				}
			}
			for _, entity := range entities {
				if !c.window.includes(entity) {
					continue
				}
				child := *c
				child.node = n
				child.entity = entity
				child.edge = nil
				if e.body.evaluate(&child) {
					if c.window != nil && c.output != nil {
						c.output.MatchedService = traceMatched(entity, c.view, n)
					}
					return true
				}
			}
		}
	} else {
		for _, edge := range c.view.edges {
			if !e.source.matches(edge.source) || !e.destination.matches(edge.destination) || !c.window.includes(edge.entity) {
				continue
			}
			child := *c
			child.edge = edge
			child.node = nil
			child.entity = edge.entity
			if e.body.evaluate(&child) {
				if c.window != nil && c.output != nil {
					matched := traceMatched(edge.entity, c.view, edge.destination)
					matched["DestinationAnnotations"] = matched["Annotations"]
					delete(matched, "Annotations")
					c.output.MatchedEdge = matched
				}
				return true
			}
		}
	}
	return false
}
func traceMatched(entity *traceEntity, v *traceView, node *traceNode) map[string]any {
	er, fa, th := entity.outcome()
	annotations := map[string]any{}
	for _, e := range v.entities {
		if node != nil && e.node != node || node == nil && e != entity {
			continue
		}
		values, _ := e.doc["annotations"].(map[string]any)
		for key, value := range values {
			a := traceAnnotation(value)
			if a == nil {
				continue
			}
			entry := map[string]any{"BooleanValue": nil, "NumberValue": nil, "StringValue": nil}
			switch x := value.(type) {
			case bool:
				entry["BooleanValue"] = x
			case float64:
				entry["NumberValue"] = x
			case string:
				entry["StringValue"] = x
			}
			existing, _ := annotations[key].([]any)
			annotations[key] = append(existing, entry)
		}
	}
	var latency any
	if d, ok := entity.duration(); ok {
		latency = d
	}
	return map[string]any{"Annotations": annotations, "HasError": er, "HasFault": fa, "HasThrottle": th, "ResponseTime": latency}
}

func (f *traceFilter) match(view *traceView, serviceWindow *traceWindow, output *api.TraceSummary) bool {
	if view == nil {
		return false
	}
	if f == nil || f.expression == nil {
		return true
	}
	return f.expression.evaluate(&traceFilterContext{view: view, window: serviceWindow, output: output})
}

// Tokens retain case for annotation keys and quoted values; only language
// keywords are folded. This prevents annotation[Request.ID] changing meaning.
type traceFilterToken struct {
	kind, text string
	value      any
	offset     int
}
type traceFilterParser struct {
	tokens    []traceFilterToken
	at        int
	groups    map[string]string
	expanding map[string]bool
	depth     int
}

func compileTraceFilter(source string, groups map[string]string) (*traceFilter, error) {
	expression, err := traceCompile(source, groups, map[string]bool{})
	if err != nil {
		return nil, failure("InvalidRequestException", "Invalid filter expression: "+err.Error())
	}
	return &traceFilter{expression: expression}, nil
}
func traceCompile(source string, groups map[string]string, expanding map[string]bool) (traceExpression, error) {
	tokens, err := traceLex(source)
	if err != nil {
		return nil, err
	}
	p := traceFilterParser{tokens: tokens, groups: groups, expanding: expanding}
	if p.peek().kind == "eof" {
		return traceTrue{}, nil
	}
	expression, err := p.parseOr("trace")
	if err != nil {
		return nil, err
	}
	if p.peek().kind != "eof" {
		return nil, p.invalid("unexpected token")
	}
	return expression, nil
}
func traceLex(source string) ([]traceFilterToken, error) {
	tokens := []traceFilterToken{}
	for i := 0; i < len(source); {
		r, size := utf8.DecodeRuneInString(source[i:])
		if unicode.IsSpace(r) {
			i += size
			continue
		}
		start := i
		if source[i] == '"' {
			i++
			escaped := false
			for i < len(source) {
				ch := source[i]
				i++
				if ch == '"' && !escaped {
					break
				}
				if ch == '\\' && !escaped {
					escaped = true
				} else {
					escaped = false
				}
			}
			var value string
			if err := json.Unmarshal([]byte(source[start:i]), &value); err != nil {
				return nil, fmt.Errorf("invalid string at position %d", start)
			}
			tokens = append(tokens, traceFilterToken{kind: "string", text: value, value: value, offset: start})
			continue
		}
		if source[i] == '#' {
			i++
			if i >= len(source) || source[i] != '[' {
				return nil, fmt.Errorf("expected JSON array at position %d", i)
			}
			decoder := json.NewDecoder(strings.NewReader(source[i:]))
			var value any
			if err := decoder.Decode(&value); err != nil {
				return nil, fmt.Errorf("invalid root cause JSON at position %d", i)
			}
			if _, ok := value.([]any); !ok {
				return nil, fmt.Errorf("expected root cause JSON array")
			}
			i += int(decoder.InputOffset())
			tokens = append(tokens, traceFilterToken{kind: "json", value: value, offset: start})
			continue
		}
		if strings.ContainsRune("(){}[],:!<>=", r) {
			i += size
			text := source[start:i]
			if i < len(source) && source[i] == '=' && (text == "!" || text == "<" || text == ">") {
				i++
				text += "="
			}
			tokens = append(tokens, traceFilterToken{kind: text, text: text, offset: start})
			continue
		}
		for i < len(source) {
			r, size = utf8.DecodeRuneInString(source[i:])
			if unicode.IsSpace(r) || strings.ContainsRune("(){}[],:!<>=\"#", r) {
				break
			}
			i += size
		}
		if i == start {
			return nil, fmt.Errorf("invalid character at position %d", i)
		}
		text := source[start:i]
		token := traceFilterToken{kind: "word", text: text, offset: start}
		if number, err := strconv.ParseFloat(text, 64); err == nil && !math.IsInf(number, 0) && !math.IsNaN(number) {
			token.kind = "number"
			token.value = number
		}
		tokens = append(tokens, token)
	}
	tokens = append(tokens, traceFilterToken{kind: "eof", offset: len(source)})
	return tokens, nil
}
func (p *traceFilterParser) peek() traceFilterToken { return p.tokens[p.at] }
func (p *traceFilterParser) take() traceFilterToken {
	t := p.peek()
	if t.kind != "eof" {
		p.at++
	}
	return t
}
func (p *traceFilterParser) accept(kind string) bool {
	t := p.peek()
	if t.kind == kind || t.kind == "word" && strings.EqualFold(t.text, kind) {
		p.at++
		return true
	}
	return false
}
func (p *traceFilterParser) require(kind string) error {
	if p.accept(kind) {
		return nil
	}
	return p.invalid("expected " + kind)
}
func (p *traceFilterParser) invalid(message string) error {
	return fmt.Errorf("%s at position %d", message, p.peek().offset)
}
func (p *traceFilterParser) parseOr(scope string) (traceExpression, error) {
	left, err := p.parseAnd(scope)
	if err != nil {
		return nil, err
	}
	for p.accept("or") {
		right, err := p.parseAnd(scope)
		if err != nil {
			return nil, err
		}
		left = traceLogical{operator: "or", left: left, right: right}
	}
	return left, nil
}
func (p *traceFilterParser) parseAnd(scope string) (traceExpression, error) {
	left, err := p.parseUnary(scope)
	if err != nil {
		return nil, err
	}
	for {
		explicit := p.accept("and")
		t := p.peek()
		if !explicit && (t.kind == "eof" || t.kind == ")" || t.kind == "}" || t.kind == "word" && strings.EqualFold(t.text, "or")) {
			break
		}
		right, err := p.parseUnary(scope)
		if err != nil {
			return nil, err
		}
		left = traceLogical{operator: "and", left: left, right: right}
	}
	return left, nil
}
func (p *traceFilterParser) parseUnary(scope string) (traceExpression, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		return nil, p.invalid("expression nesting is too deep")
	}
	if p.accept("!") || p.accept("not") {
		child, err := p.parseUnary(scope)
		return traceLogical{operator: "not", left: child}, err
	}
	if p.accept("(") {
		expression, err := p.parseOr(scope)
		if err != nil {
			return nil, err
		}
		return expression, p.require(")")
	}
	token := p.take()
	if token.kind != "word" {
		return nil, p.invalid("expected a filter keyword")
	}
	field := strings.ToLower(token.text)
	if field == "service" || field == "edge" {
		if scope != "trace" {
			return nil, p.invalid("service and edge selectors require trace scope")
		}
		return p.parseSelector(field)
	}
	if strings.HasPrefix(field, "rootcause.") && field != "rootcause.json" {
		if scope != "trace" {
			return nil, p.invalid("root cause selectors require trace scope")
		}
		return p.parseCause(field)
	}
	if strings.HasPrefix(field, "annotation.") {
		field = "annotation." + token.text[len("annotation."):]
	}
	if strings.HasPrefix(field, "source.annotation.") {
		field = "source.annotation." + token.text[len("source.annotation."):]
	} else if strings.HasPrefix(field, "destination.annotation.") {
		field = "destination.annotation." + token.text[len("destination.annotation."):]
	}
	for _, prefix := range []string{"annotation.", "source.annotation.", "destination.annotation."} {
		if strings.HasPrefix(field, prefix) && strings.Contains(strings.TrimPrefix(field, prefix), ".") {
			return nil, p.invalid("annotation keys containing dots require brackets")
		}
	}
	if field == "annotation" || field == "source.annotation" || field == "destination.annotation" {
		if err := p.require("["); err != nil {
			return nil, err
		}
		key := p.take()
		if key.kind != "word" && key.kind != "string" && key.kind != "number" {
			return nil, p.invalid("expected annotation key")
		}
		if err := p.require("]"); err != nil {
			return nil, err
		}
		field += "." + key.text
	}
	if !traceFilterFieldValid(field, scope) {
		return nil, p.invalid("unknown keyword " + field + " in " + scope + " scope")
	}
	operator := ""
	next := p.peek()
	switch strings.ToLower(next.text) {
	case "=", "!=", "<", "<=", ">", ">=", "contains", "beginswith", "endswith":
		operator = strings.ToLower(p.take().text)
	}
	if operator == "" {
		if field == "group.name" || field == "group.arn" || field == "rootcause.json" {
			return nil, p.invalid("comparison required")
		}
		return traceComparison{field: field}, nil
	}
	literal := p.take()
	var value any
	switch literal.kind {
	case "string", "number", "json":
		value = literal.value
	case "word":
		if strings.EqualFold(literal.text, "true") {
			value = true
		} else if strings.EqualFold(literal.text, "false") {
			value = false
		} else {
			return nil, p.invalid("expected quoted string, number, or boolean")
		}
	default:
		return nil, p.invalid("expected comparison value")
	}
	if field == "group.name" || field == "group.arn" {
		name, ok := value.(string)
		if !ok || (operator != "=" && operator != "!=") {
			return nil, p.invalid("group requires string equality")
		}
		expression, exists := p.groups[name]
		var child traceExpression = traceFalse{}
		if exists {
			if p.expanding[name] || len(p.expanding) > 64 {
				return nil, p.invalid("cyclic group reference")
			}
			p.expanding[name] = true
			compiled, err := traceCompile(expression, p.groups, p.expanding)
			delete(p.expanding, name)
			if err != nil {
				return nil, err
			}
			child = compiled
		}
		if operator == "!=" {
			child = traceLogical{operator: "not", left: child}
		}
		return child, nil
	}
	if field == "rootcause.json" {
		if literal.kind != "json" || (operator != "=" && operator != "!=") {
			return nil, p.invalid("rootcause.json requires JSON equality")
		}
		return traceCauseJSON{expected: value, negated: operator == "!="}, nil
	}
	if literal.kind == "json" {
		return nil, p.invalid("JSON is only valid with rootcause.json")
	}
	kind := traceFilterFieldKind(field)
	if kind == "boolean" && operator != "=" && operator != "!=" {
		return nil, p.invalid("invalid boolean operator")
	}
	if kind == "string" && operator != "=" && operator != "!=" && operator != "contains" && operator != "beginswith" && operator != "endswith" {
		return nil, p.invalid("invalid string operator")
	}
	if kind == "number" && (operator == "contains" || operator == "beginswith" || operator == "endswith") {
		return nil, p.invalid("invalid numeric operator")
	}
	return traceComparison{field: field, operator: operator, value: value}, nil
}
func (p *traceFilterParser) parseSelector(kind string) (traceExpression, error) {
	selector := traceSelector{kind: kind, body: traceTrue{}}
	if p.accept("(") {
		if !p.accept(")") {
			id, err := p.parseID()
			if err != nil {
				return nil, err
			}
			selector.source = id
			if kind == "edge" {
				if err = p.require(","); err != nil {
					return nil, err
				}
				id, err = p.parseID()
				if err != nil {
					return nil, err
				}
				selector.destination = id
			}
			if err = p.require(")"); err != nil {
				return nil, err
			}
		}
	}
	if p.accept("{") {
		body, err := p.parseOr(kind)
		if err != nil {
			return nil, err
		}
		selector.body = body
		if err = p.require("}"); err != nil {
			return nil, err
		}
	}
	return selector, nil
}
func (p *traceFilterParser) parseID() (traceSelectorID, error) {
	id := traceSelectorID{}
	if p.peek().kind == "string" {
		text := p.take().text
		id.name = &text
		return id, nil
	}
	if !p.accept("id") {
		return id, p.invalid("expected service name or id()")
	}
	if err := p.require("("); err != nil {
		return id, err
	}
	seen := map[string]bool{}
	for {
		field := strings.ToLower(p.take().text)
		if field != "name" && field != "type" && field != "account.id" {
			return id, p.invalid("invalid service identity field")
		}
		if seen[field] {
			return id, p.invalid("duplicate service identity field")
		}
		seen[field] = true
		if err := p.require(":"); err != nil {
			return id, err
		}
		value := p.take()
		if value.kind != "string" {
			return id, p.invalid("service identity requires a string")
		}
		switch field {
		case "name":
			id.name = &value.text
		case "type":
			id.kind = &value.text
		case "account.id":
			id.account = &value.text
		}
		if p.accept(")") {
			break
		}
		if err := p.require(","); err != nil {
			return id, err
		}
	}
	return id, nil
}
func traceFilterFieldKind(field string) string {
	switch field {
	case "ok", "error", "fault", "throttle", "partial", "inferred", "first", "last", "remote", "root":
		return "boolean"
	case "duration", "responsetime", "http.status", "index", "coverage":
		return "number"
	}
	if strings.Contains(field, "annotation.") {
		return "annotation"
	}
	return "string"
}
func traceFilterFieldValid(field, scope string) bool {
	if strings.HasPrefix(field, "annotation.") {
		return len(field) > len("annotation.") && (scope == "trace" || scope == "service" || scope == "edge")
	}
	if strings.HasPrefix(field, "source.annotation.") || strings.HasPrefix(field, "destination.annotation.") {
		return scope == "edge"
	}
	switch field {
	case "group.name", "group.arn", "rootcause.json":
		return scope == "trace"
	case "first", "last", "index":
		return strings.HasPrefix(scope, "rootcause.")
	case "coverage":
		return scope == "rootcause.responsetime.entity"
	case "remote":
		return strings.HasSuffix(scope, ".entity")
	case "message":
		return strings.HasSuffix(scope, ".exception")
	case "name":
		return scope == "service" || strings.HasPrefix(scope, "rootcause.")
	case "type":
		return scope == "service" || strings.HasSuffix(scope, ".service")
	case "root":
		return scope == "service"
	case "inferred":
		return scope == "trace" || scope == "service" || strings.HasSuffix(scope, ".service")
	case "ok", "error", "fault", "throttle", "partial", "duration", "responsetime", "http.status", "http.url", "http.method", "http.useragent", "http.clientip", "user", "availabilityzone", "instance.id", "resource.arn":
		return scope == "trace" || scope == "service" || scope == "edge"
	}
	return false
}
