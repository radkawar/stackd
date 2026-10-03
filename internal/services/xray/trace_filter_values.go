package xray

import (
	"strings"
)

func traceFilterValues(c *traceFilterContext, field string) []any {
	if c.fields != nil {
		value, ok := c.fields[field]
		if ok {
			return []any{value}
		}
		return nil
	}
	entities := c.view.entities
	if strings.HasPrefix(field, "source.") || strings.HasPrefix(field, "destination.") {
		if c.edge == nil {
			return nil
		}
		node := c.edge.source
		if strings.HasPrefix(field, "destination.") {
			node = c.edge.destination
		}
		child := *c
		child.node = node
		child.edge = nil
		child.entity = nil
		return traceFilterValues(&child, field[strings.IndexByte(field, '.')+1:])
	}
	if c.node != nil {
		entities = nil
		for _, e := range c.view.entities {
			if e.node == c.node {
				entities = append(entities, e)
			}
		}
	} else if c.entity != nil {
		entities = []*traceEntity{c.entity}
	}
	if strings.HasPrefix(field, "annotation.") {
		key := strings.TrimPrefix(field, "annotation.")
		out := []any{}
		for _, e := range entities {
			if value := tracePath(e.doc, "annotations", key); value != nil {
				out = append(out, value)
			}
		}
		return out
	}
	switch field {
	case "user", "availabilityzone", "instance.id", "resource.arn":
		path := []string{"user"}
		switch field {
		case "availabilityzone":
			path = []string{"aws", "ec2", "availability_zone"}
		case "instance.id":
			path = []string{"aws", "ec2", "instance_id"}
		case "resource.arn":
			path = []string{"resource_arn"}
		}
		out := []any{}
		for _, e := range entities {
			if value := tracePath(e.doc, path...); value != nil {
				out = append(out, value)
			}
		}
		return out
	case "partial":
		return []any{bool(*c.view.Summary.IsPartial)}
	case "inferred":
		if c.node != nil {
			return []any{c.node.inferred}
		}
		for _, n := range c.view.nodes {
			if n.inferred {
				return []any{true}
			}
		}
		return []any{false}
	case "root":
		if c.node != nil {
			return []any{c.node.root}
		}
		return nil
	case "name":
		if c.node != nil {
			return []any{c.node.identity.name}
		}
		return nil
	case "type":
		if c.node != nil && c.node.identity.kind != "" {
			return []any{c.node.identity.kind}
		}
		return nil
	case "duration":
		if c.entity == nil {
			if c.view.Summary.Duration == nil {
				return nil
			}
			return []any{float64(*c.view.Summary.Duration)}
		}
	case "responsetime":
		if c.entity == nil {
			if c.view.Summary.ResponseTime == nil {
				return nil
			}
			return []any{float64(*c.view.Summary.ResponseTime)}
		}
	}
	entity := c.entity
	if entity == nil {
		entity = c.view.root
	}
	if entity == nil {
		return nil
	}
	switch field {
	case "duration", "responsetime":
		d, ok := entity.duration()
		if ok {
			return []any{d}
		}
	case "ok", "error", "fault", "throttle":
		er, fa, th := entity.outcome()
		switch field {
		case "ok":
			return []any{!er && !fa && !th}
		case "error":
			return []any{er}
		case "fault":
			return []any{fa}
		case "throttle":
			return []any{th}
		}
	case "http.status":
		if status := tracePath(entity.doc, "http", "response", "status"); status != nil {
			return []any{status}
		}
	case "http.url", "http.method", "http.useragent", "http.clientip":
		key := strings.TrimPrefix(field, "http.")
		switch key {
		case "useragent":
			key = "user_agent"
		case "clientip":
			key = "client_ip"
		}
		if value := tracePath(entity.doc, "http", "request", key); value != nil {
			return []any{value}
		}
	}
	return nil
}

type traceCauseSelector struct {
	category, level string
	body            traceExpression
}

func (p *traceFilterParser) parseCause(field string) (traceExpression, error) {
	parts := strings.Split(field, ".")
	if len(parts) != 3 {
		return nil, p.invalid("invalid root cause selector")
	}
	category, level := parts[1], parts[2]
	if category != "error" && category != "fault" && category != "responsetime" {
		return nil, p.invalid("invalid root cause category")
	}
	if level != "service" && level != "entity" && level != "exception" {
		return nil, p.invalid("invalid root cause level")
	}
	if category == "responsetime" && level == "exception" {
		return nil, p.invalid("response time causes have no exceptions")
	}
	if err := p.require("{"); err != nil {
		return nil, err
	}
	body, err := p.parseOr(field)
	if err != nil {
		return nil, err
	}
	if err = p.require("}"); err != nil {
		return nil, err
	}
	return traceCauseSelector{category: category, level: level, body: body}, nil
}

func (v *traceView) rootCauseDocuments(category string) []any {
	// Cause projections populate this cache directly from the decoded topology.
	return v.causes[category]
}
func traceCauseFields(document map[string]any, index, length int) map[string]any {
	fields := make(map[string]any, len(document)+3)
	for name, value := range document {
		if value != nil {
			fields[strings.ToLower(name)] = value
		}
	}
	fields["index"] = float64(index)
	fields["first"] = index == 0
	fields["last"] = index == length-1
	return fields
}
func (e traceCauseSelector) evaluate(c *traceFilterContext) bool {
	for _, value := range c.view.rootCauseDocuments(e.category) {
		cause, _ := value.(map[string]any)
		services, _ := cause["Services"].([]any)
		for i, value := range services {
			service, _ := value.(map[string]any)
			if e.level == "service" {
				child := *c
				child.fields = traceCauseFields(service, i, len(services))
				if e.body.evaluate(&child) {
					return true
				}
				continue
			}
			entities, _ := service["EntityPath"].([]any)
			for j, value := range entities {
				entity, _ := value.(map[string]any)
				if e.level == "entity" {
					child := *c
					child.fields = traceCauseFields(entity, j, len(entities))
					if e.body.evaluate(&child) {
						return true
					}
					continue
				}
				exceptions, _ := entity["Exceptions"].([]any)
				for k, value := range exceptions {
					exception, _ := value.(map[string]any)
					child := *c
					child.fields = traceCauseFields(exception, k, len(exceptions))
					if e.body.evaluate(&child) {
						return true
					}
				}
			}
		}
	}
	return false
}

type traceCauseJSON struct {
	expected any
	negated  bool
}

func (e traceCauseJSON) evaluate(c *traceFilterContext) bool {
	matched := false
	for _, category := range []string{"error", "fault", "responsetime"} {
		if traceJSONSubset(e.expected, c.view.rootCauseDocuments(category)) {
			matched = true
			break
		}
	}
	return matched != e.negated
}
func traceJSONSubset(expected, actual any) bool {
	switch e := expected.(type) {
	case map[string]any:
		a, ok := actual.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range e {
			candidate, exists := a[key]
			if !exists || !traceJSONSubset(value, candidate) {
				return false
			}
		}
		return true
	case []any:
		a, ok := actual.([]any)
		if !ok {
			return false
		}
		at := 0
		// Omitted entities are wildcards, but the supplied path order is meaningful.
		for _, value := range e {
			found := false
			for at < len(a) {
				candidate := a[at]
				at++
				if traceJSONSubset(value, candidate) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	default:
		return expected == actual
	}
}
