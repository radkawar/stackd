package asl

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

func (c *compiler) error(code, message, location string) {
	c.diagnostics = append(c.diagnostics, Diagnostic{Severity: "ERROR", Code: code, Message: message, Location: location})
}

func (c *compiler) warning(code, message, location string) {
	c.diagnostics = append(c.diagnostics, Diagnostic{Severity: "WARNING", Code: code, Message: message, Location: location})
}

func (c *compiler) schema(message, location string) {
	c.error("SCHEMA_VALIDATION_FAILED", message, location)
}

func (c *compiler) object(value any, location string) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		c.schema("Expected an object", location)
		return map[string]any{}
	}
	return object
}

func (c *compiler) array(value any, location string, nonempty bool) []any {
	array, ok := value.([]any)
	if !ok {
		c.schema("Expected an array", location)
		return nil
	}
	if nonempty && len(array) == 0 {
		c.schema("Array must not be empty", location)
	}
	return array
}

func (c *compiler) fields(object map[string]any, allowed, location string) {
	set := make(map[string]bool)
	for _, field := range strings.Fields(allowed) {
		set[field] = true
	}
	for _, field := range compilerKeys(object) {
		if !set[field] {
			c.schema("Field '"+field+"' is not supported here", compilerLocation(location, field))
		}
	}
}

func (c *compiler) optionalString(object map[string]any, field, location string) string {
	value, exists := object[field]
	if !exists {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		c.schema(field+" must be a string", compilerLocation(location, field))
	}
	return text
}

func (c *compiler) requiredString(object map[string]any, field, location string) string {
	text := c.optionalString(object, field, location)
	if text == "" {
		c.schema(field+" must be a non-empty string", compilerLocation(location, field))
	}
	return text
}

func (c *compiler) exactlyOne(object map[string]any, fields []string, location string) {
	count := 0
	for _, field := range fields {
		if _, exists := object[field]; exists {
			count++
		}
	}
	if count != 1 {
		c.schema("Exactly one of "+strings.Join(fields, ", ")+" is required", location)
	}
}

func (c *compiler) enum(object map[string]any, field, fallback, values, location string) string {
	if _, exists := object[field]; !exists {
		return fallback
	}
	text := c.optionalString(object, field, location)
	for _, allowed := range strings.Fields(values) {
		if text == allowed {
			return text
		}
	}
	c.schema(field+" must be one of "+values, compilerLocation(location, field))
	return text
}

func (c *compiler) transitions(definition *Definition, location string) {
	if definition.States[definition.StartAt] == nil {
		c.error("MISSING_TRANSITION_TARGET", "Missing 'StartAt' target: "+definition.StartAt, location+"/StartAt")
	}
	type edge struct{ target, location string }
	edges := make(map[string][]edge, len(definition.States))
	terminal := false
	for _, name := range compilerStateNames(definition) {
		state := definition.States[name]
		at := compilerLocation(location+"/States", name)
		if state.End || state.Type == Succeed || state.Type == Fail {
			terminal = true
		}
		if state.Next != "" {
			edges[name] = append(edges[name], edge{state.Next, at + "/Next"})
		}
		if state.Choice != nil {
			for i, rule := range state.Choice.Rules {
				if rule.Next != "" {
					edges[name] = append(edges[name], edge{rule.Next, fmt.Sprintf("%s/Choices[%d]/Next", at, i)})
				}
			}
			if state.Choice.Default != "" {
				edges[name] = append(edges[name], edge{state.Choice.Default, at + "/Default"})
			}
		}
		for i, catcher := range state.Catch {
			if catcher.Next != "" {
				edges[name] = append(edges[name], edge{catcher.Next, fmt.Sprintf("%s/Catch[%d]/Next", at, i)})
			}
		}
		for _, edge := range edges[name] {
			if definition.States[edge.target] == nil {
				c.error("MISSING_TRANSITION_TARGET", "Missing transition target: "+edge.target, edge.location)
			}
		}
	}
	if !terminal {
		c.error("MISSING_END_STATE", "Workflow has no terminal state", location)
	}
	reached := make(map[string]bool, len(definition.States))
	pending := []string{definition.StartAt}
	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if reached[name] || definition.States[name] == nil {
			continue
		}
		reached[name] = true
		for _, edge := range edges[name] {
			pending = append(pending, edge.target)
		}
	}
	for _, name := range compilerStateNames(definition) {
		if !reached[name] {
			c.error("MISSING_TRANSITION_TARGET", "State '"+name+"' is not reachable", compilerLocation(location+"/States", name))
		}
	}
}

func compilerStateNames(definition *Definition) []string {
	names := make([]string, 0, len(definition.States))
	for name := range definition.States {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *compiler) collectAssignments(states map[string]any, scope *variableScope, location string) {
	for _, stateName := range compilerKeys(states) {
		state, ok := states[stateName].(map[string]any)
		if !ok {
			continue
		}
		at := compilerLocation(location, stateName)
		language := c.machineLanguage
		if override, ok := state["QueryLanguage"].(string); ok {
			language = Language(override)
		}
		c.assignmentNames(state["Assign"], scope, language, at+"/Assign")
		for _, field := range []string{"Choices", "Catch"} {
			entries, _ := state[field].([]any)
			for i, entry := range entries {
				if object, ok := entry.(map[string]any); ok {
					c.assignmentNames(object["Assign"], scope, language, fmt.Sprintf("%s/%s[%d]/Assign", at, field, i))
				}
			}
		}
	}
}

func (c *compiler) assignmentNames(value any, scope *variableScope, language Language, location string) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	for _, key := range compilerKeys(object) {
		name := key
		if language == JSONPath {
			name = strings.TrimSuffix(key, ".$")
		}
		if !compilerVariableName(name) || name == "states" {
			c.schema("Invalid workflow variable name: "+name, compilerLocation(location, key))
			continue
		}
		for parent := scope.parent; parent != nil; parent = parent.parent {
			if parent.variables[name] {
				c.error("DUPLICATE_VARIABLE_NAME", "The variable name '"+name+"' was already defined in a parent scope.", compilerLocation(location, key))
				break
			}
		}
		scope.variables[name] = true
	}
}

func compilerVariableName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > 80 {
		return false
	}
	for i, r := range name {
		start := unicode.IsLetter(r) || unicode.In(r, unicode.Nl, unicode.Other_ID_Start)
		if i == 0 {
			if !start {
				return false
			}
			continue
		}
		if !start && !unicode.In(r, unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc, unicode.Other_ID_Continue) {
			return false
		}
	}
	return true
}

func (c *compiler) references(references []string, ctx compileContext, location string) {
	for _, reference := range references {
		if reference == "$states" {
			continue
		}
		if strings.HasPrefix(reference, "$states.") {
			field := strings.SplitN(strings.TrimPrefix(reference, "$states."), ".", 2)[0]
			switch field {
			case "input", "context":
			case "result":
				if !ctx.result {
					c.error("UNSUPPORTED_JSONATA_EXPRESSION", "Field '$states.result' does not exist.", location)
				}
			case "errorOutput":
				if !ctx.errorOutput {
					c.error("UNSUPPORTED_JSONATA_EXPRESSION", "Field '$states.errorOutput' does not exist.", location)
				}
			default:
				c.error("UNSUPPORTED_JSONATA_EXPRESSION", "Unknown reserved states field: "+field, location)
			}
			continue
		}
		name := strings.TrimPrefix(reference, "$")
		found := false
		for scope := ctx.scope; scope != nil; scope = scope.parent {
			if scope.variables[name] {
				found = true
				break
			}
			if !scope.readParent {
				break
			}
		}
		if !found {
			c.warning("POSSIBLY_UNDEFINED_VARIABLE", "Variable '"+name+"' is possibly not defined.", location)
		}
	}
}

func (c *compiler) retriers(object map[string]any, location string) []Retrier {
	value, exists := object["Retry"]
	if !exists {
		return nil
	}
	entries := c.array(value, location+"/Retry", false)
	retriers := make([]Retrier, 0, len(entries))
	ctx := compileContext{language: JSONPath}
	for i, value := range entries {
		at := fmt.Sprintf("%s/Retry[%d]", location, i)
		object := c.object(value, at)
		c.fields(object, "ErrorEquals IntervalSeconds MaxAttempts BackoffRate MaxDelaySeconds JitterStrategy", at)
		retrier := Retrier{ErrorEquals: c.errorEquals(object, i == len(entries)-1, at), IntervalSeconds: 1, MaxAttempts: 3, BackoffRate: 2, JitterStrategy: "NONE"}
		if value := c.integer(object, "IntervalSeconds", "", 1, 99999999, ctx, at); value != nil {
			retrier.IntervalSeconds = value.Value
		}
		if value := c.integer(object, "MaxAttempts", "", 0, 99999999, ctx, at); value != nil {
			retrier.MaxAttempts = value.Value
		}
		if value := c.integer(object, "MaxDelaySeconds", "", 1, 31622400, ctx, at); value != nil {
			retrier.MaxDelaySeconds = value.Value
		}
		if value := c.number(object, "BackoffRate", "", 1, 1.7976931348623157e308, ctx, at); value != nil {
			retrier.BackoffRate = value.Value
		}
		retrier.JitterStrategy = c.enum(object, "JitterStrategy", "NONE", "NONE FULL", at)
		retriers = append(retriers, retrier)
	}
	return retriers
}

func (c *compiler) catchers(object map[string]any, ctx compileContext, location string) []Catcher {
	value, exists := object["Catch"]
	if !exists {
		return nil
	}
	entries := c.array(value, location+"/Catch", false)
	catchers := make([]Catcher, 0, len(entries))
	ctx.errorOutput = true
	for i, value := range entries {
		at := fmt.Sprintf("%s/Catch[%d]", location, i)
		object := c.object(value, at)
		fields := "ErrorEquals Next Assign"
		if ctx.language == JSONPath {
			fields += " ResultPath"
		} else {
			fields += " Output"
		}
		c.fields(object, fields, at)
		catcher := Catcher{ErrorEquals: c.errorEquals(object, i == len(entries)-1, at), Next: c.requiredString(object, "Next", at), Assign: c.assignment(object, ctx, at)}
		if ctx.language == JSONPath {
			catcher.ResultPath = c.resultPath(object, ctx, at)
		} else {
			catcher.Output = c.template(object, "Output", false, ctx, at)
		}
		catchers = append(catchers, catcher)
	}
	return catchers
}

func (c *compiler) errorEquals(object map[string]any, last bool, location string) []string {
	array := c.array(object["ErrorEquals"], location+"/ErrorEquals", true)
	result := make([]string, 0, len(array))
	for i, value := range array {
		text, ok := value.(string)
		if !ok || text == "" {
			c.schema("ErrorEquals entries must be non-empty strings", fmt.Sprintf("%s/ErrorEquals[%d]", location, i))
			continue
		}
		if text == "States.ALL" && (len(array) != 1 || !last) {
			c.schema("States.ALL must appear alone in the last retry or catch entry", location+"/ErrorEquals")
		}
		result = append(result, text)
	}
	return result
}

func (c *compiler) templateWarnings(value any, location string) {
	switch value := value.(type) {
	case map[string]any:
		for _, key := range compilerKeys(value) {
			child := value[key]
			if text, ok := child.(string); ok && !strings.HasSuffix(key, ".$") && compilerLooksDynamic(text) {
				c.warning("NO_DOLLAR", "The value of '"+key+"' looks like a JSONPath or intrinsic function. Use '"+key+".$' to evaluate it at runtime.", location)
			}
			c.templateWarnings(child, location)
		}
	case []any:
		for _, child := range value {
			c.templateWarnings(child, location)
		}
	}
}

func compilerLooksDynamic(value string) bool {
	return value == "$" || strings.HasPrefix(value, "$.") || strings.HasPrefix(value, "$[") || strings.HasPrefix(value, "$$.") || strings.HasPrefix(value, "States.")
}

func compilerStaticResultLooksDynamic(value any) bool {
	switch value := value.(type) {
	case string:
		return compilerLooksDynamic(value)
	case map[string]any:
		for _, child := range value {
			if compilerStaticResultLooksDynamic(child) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if compilerStaticResultLooksDynamic(child) {
				return true
			}
		}
	}
	return false
}
