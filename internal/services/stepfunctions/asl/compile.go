package asl

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
)

type compiler struct {
	diagnostics     []Diagnostic
	names           map[string]bool
	labels          map[string]bool
	stateOrder      map[string][]string
	rootPath        *Path
	machineLanguage Language
}

type variableScope struct {
	variables  map[string]bool
	parent     *variableScope
	readParent bool
}

type compileContext struct {
	language    Language
	scope       *variableScope
	result      bool
	errorOutput bool
}

// Compile validates the complete definition and compiles every path, expression,
// and payload template. No service availability or permissions are consulted.
func Compile(source string) (*Definition, []Diagnostic) {
	c := &compiler{names: make(map[string]bool), labels: make(map[string]bool), stateOrder: make(map[string][]string)}
	if strings.TrimSpace(source) == "" || strings.TrimSpace(source) == "null" {
		c.error("MISSING_DESCRIPTION", "State machine definition must not be empty", "")
		return nil, c.diagnostics
	}
	decoder := json.NewDecoder(strings.NewReader(source))
	decoder.UseNumber()
	value, err := c.decode(decoder, "", 0)
	if err == nil {
		var extra any
		if e := decoder.Decode(&extra); e != io.EOF {
			err = fmt.Errorf("definition must contain exactly one JSON value")
		}
	}
	if err != nil {
		c.error("INVALID_JSON_DESCRIPTION", err.Error(), "")
		return nil, c.diagnostics
	}
	object := c.object(value, "")
	c.machineLanguage = c.language(object, JSONPath, "")
	c.rootPath, err = CompilePath("$", true)
	if err != nil {
		c.schema(err.Error(), "")
		return nil, c.diagnostics
	}
	definition := c.definition(object, "", nil, true, false, 0)
	for _, diagnostic := range c.diagnostics {
		if diagnostic.Severity == "ERROR" {
			return nil, c.diagnostics
		}
	}
	return definition, c.diagnostics
}

func (c *compiler) decode(d *json.Decoder, location string, depth int) (any, error) {
	if depth > 10000 {
		return nil, fmt.Errorf("JSON nesting is too deep")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for d.More() {
			token, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := token.(string)
			if !ok {
				return nil, fmt.Errorf("object member must be a string")
			}
			at := compilerLocation(location, key)
			if _, exists := object[key]; exists {
				code := "SCHEMA_VALIDATION_FAILED"
				if strings.HasSuffix(location, "/States") {
					code = "DUPLICATE_STATE_NAME"
				}
				c.error(code, "Duplicate field '"+key+"'", at)
			} else if strings.HasSuffix(location, "/States") {
				c.stateOrder[location] = append(c.stateOrder[location], key)
			}
			value, err := c.decode(d, at, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for d.More() {
			value, err := c.decode(d, fmt.Sprintf("%s[%d]", location, len(array)), depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if _, err := d.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter")
	}
}

func (c *compiler) definition(object map[string]any, location string, parent *variableScope, root, distributed bool, depth int) *Definition {
	if depth > 25 {
		c.error("TOO_DEEPLY_NESTED", "State nesting exceeds the maximum depth of 25", location)
		return nil
	}
	fields := "StartAt States Comment"
	if root {
		fields += " QueryLanguage TimeoutSeconds Version"
	} else if strings.HasSuffix(location, "/ItemProcessor") {
		fields += " ProcessorConfig"
	}
	c.fields(object, fields, location)
	c.optionalString(object, "Comment", location)
	if root {
		if _, exists := object["Version"]; exists {
			if version := c.optionalString(object, "Version", location); version != "1.0" {
				c.schema("Version must be 1.0", location+"/Version")
			}
		}
	}
	states := c.object(object["States"], location+"/States")
	if len(states) == 0 {
		c.schema("States must contain at least one state", location+"/States")
	}
	scope := &variableScope{variables: make(map[string]bool), parent: parent, readParent: !distributed}
	c.collectAssignments(states, scope, location+"/States")
	definition := &Definition{StartAt: c.requiredString(object, "StartAt", location), States: make(map[string]*State, len(states)), Language: c.machineLanguage}
	if root {
		if value := c.integer(object, "TimeoutSeconds", "", 1, math.MaxInt32, compileContext{language: JSONPath}, location); value != nil {
			definition.TimeoutSeconds = value.Value
		}
	}
	for name := range scope.variables {
		definition.Variables = append(definition.Variables, name)
	}
	sort.Strings(definition.Variables)
	for _, name := range c.stateOrder[location+"/States"] {
		at := compilerLocation(location+"/States", name)
		if name == "" || utf8.RuneCountInString(name) > 80 {
			c.error("INVALID_STATE_NAME", "State names must contain between 1 and 80 characters", at)
		}
		if c.names[name] {
			c.error("DUPLICATE_STATE_NAME", "Duplicate state name: "+name, at)
		}
		c.names[name] = true
		definition.States[name] = c.state(name, c.object(states[name], at), at, scope, depth)
	}
	c.transitions(definition, location)
	return definition
}

func (c *compiler) state(name string, object map[string]any, location string, scope *variableScope, depth int) *State {
	state := &State{Name: name, Type: StateType(c.requiredString(object, "Type", location)), Language: c.language(object, c.machineLanguage, location)}
	ctx := compileContext{language: state.Language, scope: scope}
	fields := "Type QueryLanguage Comment"
	c.optionalString(object, "Comment", location)
	switch state.Type {
	case Pass, Task, Wait, Parallel, Map:
		fields += " Next End Assign"
	case Choice:
		fields += " Assign Choices Default"
	case Succeed, Fail:
	default:
		c.schema("Invalid state type: "+string(state.Type), location+"/Type")
	}
	if state.Type != Choice && state.Type != Succeed && state.Type != Fail {
		state.Next = c.optionalString(object, "Next", location)
		if value, exists := object["End"]; exists {
			var ok bool
			state.End, ok = value.(bool)
			if !ok {
				c.schema("End must be a boolean", location+"/End")
			}
		}
		_, next := object["Next"]
		_, end := object["End"]
		if next && end {
			c.schema("A state cannot contain both Next and End", location)
		}
		if state.Next == "" && !state.End {
			c.schema("A state must have Next or End set to true", location)
		}
	}
	if state.Language == JSONPath {
		if state.Type != Fail {
			fields += " InputPath OutputPath"
			state.InputPath = c.path(object, "InputPath", false, true, true, ctx, location)
			state.OutputPath = c.path(object, "OutputPath", false, true, true, ctx, location)
		}
		switch state.Type {
		case Pass, Task, Parallel, Map:
			fields += " Parameters ResultPath"
			state.Parameters = c.template(object, "Parameters", true, ctx, location)
			state.ResultPath = c.resultPath(object, ctx, location)
		}
		switch state.Type {
		case Task, Parallel, Map:
			fields += " ResultSelector"
			state.ResultSelector = c.template(object, "ResultSelector", true, ctx, location)
		}
	} else {
		if state.Type != Fail {
			fields += " Output"
			outputCtx := ctx
			outputCtx.result = state.Type == Task || state.Type == Parallel || state.Type == Map
			state.Output = c.template(object, "Output", false, outputCtx, location)
		}
		if state.Type == Task || state.Type == Parallel {
			fields += " Arguments"
			state.Arguments = c.template(object, "Arguments", false, ctx, location)
		}
	}
	assignCtx := ctx
	assignCtx.result = state.Type == Task || state.Type == Parallel || state.Type == Map
	state.Assign = c.assignment(object, assignCtx, location)
	if state.Type == Task || state.Type == Parallel || state.Type == Map {
		fields += " Retry Catch"
		state.Retry = c.retriers(object, location)
		state.Catch = c.catchers(object, ctx, location)
	}
	switch state.Type {
	case Pass:
		state.Pass = &PassState{}
		if state.Language == JSONPath {
			fields += " Result"
			state.Pass.Result, state.Pass.HasResult = object["Result"]
		}
		if state.Pass.HasResult && compilerStaticResultLooksDynamic(state.Pass.Result) {
			c.warning("PASS_RESULT_IS_STATIC", "The Result field of a Pass state is static and is not evaluated as a path or intrinsic function.", location+"/Result")
		}
	case Task:
		fields += " Resource Credentials TimeoutSeconds HeartbeatSeconds"
		if state.Language == JSONPath {
			fields += " TimeoutSecondsPath HeartbeatSecondsPath"
		}
		state.Task = &TaskState{Resource: c.resource(object, true, location), TimeoutSeconds: c.integer(object, "TimeoutSeconds", "TimeoutSecondsPath", 1, 99999999, ctx, location), HeartbeatSeconds: c.integer(object, "HeartbeatSeconds", "HeartbeatSecondsPath", 1, 99999999, ctx, location)}
		if state.Task.TimeoutSeconds != nil && state.Task.HeartbeatSeconds != nil {
			t, h := state.Task.TimeoutSeconds, state.Task.HeartbeatSeconds
			if t.Path == nil && t.Expression == nil && h.Path == nil && h.Expression == nil && h.Value >= t.Value {
				c.schema("HeartbeatSeconds must be smaller than TimeoutSeconds", location+"/HeartbeatSeconds")
			}
		}
		if value, exists := object["Credentials"]; exists {
			credentials := c.object(value, location+"/Credentials")
			allowed := "RoleArn"
			if state.Language == JSONPath {
				allowed += " RoleArn.$"
			}
			c.fields(credentials, allowed, location+"/Credentials")
			role := c.stringValue(credentials, "RoleArn", "RoleArn.$", true, false, ctx, location+"/Credentials")
			if role == nil {
				c.schema("Credentials requires RoleArn or RoleArn.$", location+"/Credentials")
			}
			state.Task.Credentials = &Credentials{RoleArn: role}
		}
		c.sdkParameters(state, object, location)
		c.ecsParameters(state, object, location)
	case Choice:
		state.Choice = c.choices(object, ctx, location)
		state.Choice.defaultRule = ChoiceRule{Next: state.Choice.Default, Assign: state.Assign, Output: state.Output}
	case Wait:
		fields += " Seconds Timestamp"
		if state.Language == JSONPath {
			fields += " SecondsPath TimestampPath"
		}
		c.exactlyOne(object, []string{"Seconds", "SecondsPath", "Timestamp", "TimestampPath"}, location)
		state.Wait = &WaitState{Seconds: c.integer(object, "Seconds", "SecondsPath", 0, 99999999, ctx, location), Timestamp: c.stringValue(object, "Timestamp", "TimestampPath", false, true, ctx, location)}
		if state.Wait.Seconds != nil && state.Wait.Seconds.Path != nil {
			state.Wait.Seconds.coerceIntegerString = true
		}
	case Fail:
		fields += " Error Cause"
		if state.Language == JSONPath {
			fields += " ErrorPath CausePath"
		}
		state.Fail = &FailState{Error: c.stringValue(object, "Error", "ErrorPath", true, false, ctx, location), Cause: c.stringValue(object, "Cause", "CausePath", true, false, ctx, location)}
	case Parallel:
		fields += " Branches"
		state.Parallel = &ParallelState{}
		branches := c.array(object["Branches"], location+"/Branches", true)
		for i, branch := range branches {
			at := fmt.Sprintf("%s/Branches[%d]", location, i)
			state.Parallel.Branches = append(state.Parallel.Branches, c.definition(c.object(branch, at), at, scope, false, false, depth+1))
		}
	case Map:
		fields += " ItemProcessor Iterator ItemReader ItemSelector ItemBatcher ResultWriter MaxConcurrency ToleratedFailureCount ToleratedFailurePercentage Label"
		if state.Language == JSONPath {
			fields += " ItemsPath MaxConcurrencyPath ToleratedFailureCountPath ToleratedFailurePercentagePath"
		} else {
			fields += " Items"
		}
		state.Map = c.mapState(object, ctx, location, depth, state.Parameters)
		state.Parameters = nil
	}
	c.fields(object, fields, location)
	return state
}

func (c *compiler) ecsParameters(state *State, object map[string]any, location string) {
	if !strings.HasSuffix(state.Task.Resource, ":ecs:runTask.sync") {
		return
	}
	field := "Parameters"
	if state.Language == JSONata {
		field = "Arguments"
	}
	parameters, _ := object[field].(map[string]any)
	for _, name := range []string{"Count", "StartedBy"} {
		_, present := parameters[name]
		_, dynamic := parameters[name+".$"]
		if present || dynamic {
			c.schema("The field '"+name+"' is not supported by Step Functions", location+"/"+field)
		}
	}
}

func (c *compiler) sdkParameters(state *State, object map[string]any, location string) {
	_, resource, sdk := strings.Cut(state.Task.Resource, ":aws-sdk:")
	if !sdk {
		return
	}
	serviceName, operationName, _ := strings.Cut(resource, ":")
	operationName, _, _ = strings.Cut(operationName, ".")
	if operationName == "" {
		return
	}
	service, found := awscatalog.LookupService(serviceName)
	if !found {
		for _, candidate := range awscatalog.Services() {
			if strings.TrimSuffix(path.Base(candidate.Source.Path), ".json") == serviceName {
				service, found = awscatalog.LookupService(candidate.Name)
				break
			}
		}
	}
	if !found {
		return
	}
	operation, found := service.Operation(strings.ToUpper(operationName[:1]) + operationName[1:])
	if !found {
		return
	}
	field := "Parameters"
	if state.Language == JSONata {
		field = "Arguments"
	}
	for _, err := range awsapi.ValidateSDKTemplate(service, operation.Input, object[field], state.Language == JSONPath) {
		c.schema(err.Error(), location+"/"+field)
	}
}

func (c *compiler) language(object map[string]any, inherited Language, location string) Language {
	value, exists := object["QueryLanguage"]
	if !exists {
		return inherited
	}
	text, ok := value.(string)
	if !ok || (text != string(JSONPath) && text != string(JSONata)) {
		c.schema("QueryLanguage must be JSONPath or JSONata", location+"/QueryLanguage")
		return inherited
	}
	language := Language(text)
	if c.machineLanguage == JSONata && language == JSONPath {
		c.schema("A JSONata state machine cannot contain JSONPath states", location+"/QueryLanguage")
	}
	return language
}

func (c *compiler) resource(object map[string]any, required bool, location string) string {
	resource := c.optionalString(object, "Resource", location)
	if required && resource == "" {
		c.error("INVALID_RESOURCE", "Resource must be a non-empty URI", location+"/Resource")
		return resource
	}
	if resource != "" {
		parsed, err := url.Parse(resource)
		if err != nil || parsed.Scheme == "" || strings.ContainsAny(resource, " \t\r\n") {
			c.error("INVALID_RESOURCE", "Resource must be a valid URI", location+"/Resource")
		}
	}
	return resource
}

func (c *compiler) template(object map[string]any, field string, objectOnly bool, ctx compileContext, location string) *Template {
	value, exists := object[field]
	if !exists {
		return nil
	}
	at := compilerLocation(location, field)
	if ctx.language == JSONPath {
		c.templateWarnings(value, at)
	}
	if objectOnly {
		if _, ok := value.(map[string]any); !ok {
			if text, expression := value.(string); !expression || ctx.language != JSONata || !strings.HasPrefix(text, "{%") {
				c.schema(field+" must be an object", at)
			}
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		c.schema(err.Error(), at)
		return nil
	}
	template, err := CompileTemplate(raw, ctx.language)
	if err != nil {
		c.schema(err.Error(), at)
		return nil
	}
	if template != nil {
		c.references(template.References(), ctx, at)
	}
	return template
}

func (c *compiler) assignment(object map[string]any, ctx compileContext, location string) *Template {
	if value, exists := object["Assign"]; exists {
		if _, ok := value.(map[string]any); !ok {
			c.schema("Assign must be an object", location+"/Assign")
		}
	}
	return c.template(object, "Assign", true, ctx, location)
}

func (c *compiler) expression(source string, ctx compileContext, location string) *Expression {
	expression, err := CompileExpression(source, ctx.language)
	if err != nil {
		c.schema(err.Error(), location)
		return nil
	}
	c.references(expression.References(), ctx, location)
	return expression
}

func (c *compiler) path(object map[string]any, field string, reference, nullable, defaultRoot bool, ctx compileContext, location string) *Path {
	value, exists := object[field]
	if !exists {
		if defaultRoot {
			return c.rootPath
		}
		return nil
	}
	if value == nil && nullable {
		return nil
	}
	text, ok := value.(string)
	if !ok {
		c.schema(field+" must be a path string", compilerLocation(location, field))
		return nil
	}
	path, err := CompilePath(text, reference)
	if err != nil {
		c.schema(err.Error(), compilerLocation(location, field))
		return nil
	}
	c.references(path.References(), ctx, compilerLocation(location, field))
	return path
}

func (c *compiler) resultPath(object map[string]any, ctx compileContext, location string) *Path {
	if text, ok := object["ResultPath"].(string); ok && text != "$" && !strings.HasPrefix(text, "$.") && !strings.HasPrefix(text, "$[") {
		c.schema("ResultPath must target the input, not a context or workflow variable", location+"/ResultPath")
	}
	return c.path(object, "ResultPath", true, true, true, ctx, location)
}

func (c *compiler) integer(object map[string]any, field, pathField string, minimum, maximum int64, ctx compileContext, location string) *IntegerValue {
	literal, exists := object[field]
	_, pathExists := object[pathField]
	if !exists && !pathExists {
		return nil
	}
	value := &IntegerValue{minimum: minimum, maximum: maximum, language: ctx.language}
	if exists && pathExists {
		c.schema(field+" and "+pathField+" are mutually exclusive", location)
	}
	if pathExists {
		if ctx.language != JSONPath {
			c.schema(pathField+" is only supported for JSONPath", location+"/"+pathField)
		}
		value.Path = c.path(object, pathField, true, false, false, ctx, location)
		return value
	}
	if text, ok := literal.(string); ok && ctx.language == JSONata && strings.HasPrefix(text, "{%") {
		value.Expression = c.expression(text, ctx, location+"/"+field)
		return value
	}
	number, ok := numberValue(literal)
	if !ok || math.Trunc(number) != number || number < float64(minimum) || number > float64(maximum) {
		c.schema(fmt.Sprintf("%s must be an integer between %d and %d", field, minimum, maximum), location+"/"+field)
		return value
	}
	value.Value = int64(number)
	return value
}

func (c *compiler) number(object map[string]any, field, pathField string, minimum, maximum float64, ctx compileContext, location string) *NumberValue {
	literal, exists := object[field]
	_, pathExists := object[pathField]
	if !exists && !pathExists {
		return nil
	}
	value := &NumberValue{minimum: minimum, maximum: maximum, language: ctx.language}
	if exists && pathExists {
		c.schema(field+" and "+pathField+" are mutually exclusive", location)
	}
	if pathExists {
		if ctx.language != JSONPath {
			c.schema(pathField+" is only supported for JSONPath", location+"/"+pathField)
		}
		value.Path = c.path(object, pathField, true, false, false, ctx, location)
		return value
	}
	if text, ok := literal.(string); ok && ctx.language == JSONata && strings.HasPrefix(text, "{%") {
		value.Expression = c.expression(text, ctx, location+"/"+field)
		return value
	}
	number, ok := numberValue(literal)
	if !ok || number < minimum || number > maximum {
		c.schema(fmt.Sprintf("%s must be a number between %g and %g", field, minimum, maximum), location+"/"+field)
		return value
	}
	value.Value = number
	return value
}

func (c *compiler) stringValue(object map[string]any, field, pathField string, intrinsic, timestamp bool, ctx compileContext, location string) *StringValue {
	literal, exists := object[field]
	dynamic, pathExists := object[pathField]
	if !exists && !pathExists {
		return nil
	}
	value := &StringValue{language: ctx.language, timestamp: timestamp}
	if exists && pathExists {
		c.schema(field+" and "+pathField+" are mutually exclusive", location)
	}
	if pathExists {
		if ctx.language != JSONPath {
			c.schema(pathField+" is only supported for JSONPath", location+"/"+pathField)
		}
		if text, ok := dynamic.(string); ok && intrinsic && strings.HasPrefix(text, "States.") {
			value.Expression = c.expression(text, ctx, location+"/"+pathField)
		} else {
			value.Path = c.path(object, pathField, true, false, false, ctx, location)
		}
		return value
	}
	text, ok := literal.(string)
	if !ok {
		c.schema(field+" must be a string", location+"/"+field)
		return value
	}
	if ctx.language == JSONata && strings.HasPrefix(text, "{%") {
		value.Expression = c.expression(text, ctx, location+"/"+field)
		return value
	}
	if timestamp {
		if _, ok := compilerTimestamp(text); !ok {
			c.schema(field+" must be an RFC3339 timestamp", location+"/"+field)
		}
	}
	value.Value = text
	return value
}

func compilerKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func compilerLocation(location, key string) string {
	return location + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}
