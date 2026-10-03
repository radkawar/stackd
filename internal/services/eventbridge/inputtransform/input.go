// Package inputtransform compiles EventBridge target input projections.
package inputtransform

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Definition selects at most one AWS target input mode. Generated API bindings
// own model size bounds; Compile owns the mutually exclusive modes and grammar.
type Definition struct {
	Input       *string      `json:"Input,omitempty"`
	InputPath   *string      `json:"InputPath,omitempty"`
	Transformer *Transformer `json:"InputTransformer,omitempty"`
}

// Transformer extracts named values from the original event into a template.
type Transformer struct {
	InputPathsMap map[string]string `json:"InputPathsMap,omitempty"`
	InputTemplate string            `json:"InputTemplate"`
}

// Context contains rule identity and the service time captured at admission.
type Context struct {
	RuleARN       string    `json:"rule_arn"`
	RuleName      string    `json:"rule_name"`
	IngestionTime time.Time `json:"ingestion_time"`
}

// ErrInvalidJSON means an admitted template produced invalid target input. Apply
// returns the attempted body with this error so the delivery can retain it for
// the target's dead-letter queue without rejecting the originating event.
var ErrInvalidJSON = errors.New("input transformation produced invalid JSON")

// Projection is an immutable compiled definition, safe for concurrent reuse.
type Projection struct {
	mode      uint8
	input     string
	path      path
	variables map[string]path
	template  template
}

// Compile validates a target definition without observing event data.
func Compile(definition Definition) (*Projection, error) {
	modes := 0
	for _, present := range []bool{definition.Input != nil, definition.InputPath != nil, definition.Transformer != nil} {
		if present {
			modes++
		}
	}
	if modes > 1 {
		return nil, fmt.Errorf("input modes are mutually exclusive")
	}
	projection := &Projection{}
	if definition.Input != nil {
		if *definition.Input != "" && !json.Valid([]byte(*definition.Input)) {
			return nil, fmt.Errorf("input must be valid JSON")
		}
		projection.mode, projection.input = 1, *definition.Input
	}
	if definition.InputPath != nil {
		projection.mode = 2
		if *definition.InputPath != "" {
			compiled, err := compilePath(*definition.InputPath)
			if err != nil {
				return nil, err
			}
			projection.path = compiled
		}
	}
	if definition.Transformer != nil {
		projection.mode = 3
		projection.variables = make(map[string]path, len(definition.Transformer.InputPathsMap))
		for name, source := range definition.Transformer.InputPathsMap {
			compiled, err := compilePath(source)
			if err != nil {
				return nil, fmt.Errorf("input path %q: %w", name, err)
			}
			projection.variables[name] = compiled
		}
		compiled, err := compileTemplate(definition.Transformer.InputTemplate)
		if err != nil {
			return nil, err
		}
		projection.template = compiled
	}
	return projection, nil
}

// Apply projects one admitted JSON event. The caller retains the result in the
// target delivery intent so retries cannot change input or ingestion time.
func (p *Projection) Apply(event []byte, context Context) ([]byte, error) {
	switch p.mode {
	case 0:
		return event, nil
	case 1:
		return []byte(p.input), nil
	}
	root, err := parseEvent(event)
	if err != nil {
		return nil, err
	}
	if p.mode == 2 {
		result := p.path.selectValue(root)
		if result == nil || result.kind == '0' {
			return []byte("{}"), nil
		}
		return compact(result.raw), nil
	}
	body, err := p.render(root, context)
	if err != nil {
		return nil, err
	}
	// AWS admits empty projections but the native bounded delivery capture has
	// no target or DLQ outcome for them. Do not classify them as INVALID_JSON.
	if len(body) == 0 {
		return body, nil
	}
	if !json.Valid(body) {
		if _, _, err := templateJSON(body); !p.template.multiline || err != nil {
			return body, ErrInvalidJSON
		}
	}
	return body, nil
}
