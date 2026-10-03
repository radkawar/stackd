package pipes

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"stackd/internal/services/eventbridge/eventpattern"
	"stackd/internal/services/eventbridge/inputtransform"
	"strings"
	"time"
)

type templatePart struct {
	text, variable string
	path           *inputtransform.Projection
	quoted         bool
}
type inputTemplate struct {
	parts       []templatePart
	passthrough bool
}

func compileTemplate(t string) (inputTemplate, error) {
	if t == "" {
		return inputTemplate{passthrough: true}, nil
	}
	result := inputTemplate{}
	quoted, escaped := false, false
	start := 0
	for i := 0; i < len(t); i++ {
		if t[i] == '<' {
			end := strings.IndexByte(t[i:], '>')
			if end < 0 {
				return result, fmt.Errorf("unterminated input template variable")
			}
			result.parts = append(result.parts, templatePart{text: t[start:i]})
			v := t[i+1 : i+end]
			p := templatePart{variable: v, quoted: quoted}
			if strings.HasPrefix(v, "$") {
				compiled, e := inputtransform.Compile(inputtransform.Definition{InputPath: &v})
				if e != nil {
					return result, e
				}
				p.path = compiled
			} else {
				switch v {
				case "aws.pipes.pipe-arn", "aws.pipes.pipe-name", "aws.pipes.source-arn", "aws.pipes.enrichment-arn", "aws.pipes.target-arn", "aws.pipes.event.ingestion-time", "aws.pipes.event", "aws.pipes.event.json":
				default:
					return result, fmt.Errorf("unknown input template variable %q", v)
				}
			}
			result.parts = append(result.parts, p)
			i += end
			start = i + 1
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if t[i] == '\\' {
			escaped = true
		} else if t[i] == '"' {
			quoted = !quoted
		}
	}
	result.parts = append(result.parts, templatePart{text: t[start:]})
	return result, nil
}
func (t inputTemplate) apply(event []byte, p PipeRecord, now time.Time) ([]byte, error) {
	if t.passthrough {
		return event, nil
	}
	decoded := decodeEvent(event)
	var out bytes.Buffer
	for _, part := range t.parts {
		if part.variable == "" {
			out.WriteString(part.text)
			continue
		}
		var v []byte
		var e error
		if part.path != nil {
			v, e = part.path.Apply(decoded, inputtransform.Context{})
			if e != nil {
				return nil, e
			}
			if bytes.Equal(v, []byte("{}")) {
				// The shared path projector's missing value becomes Pipes' empty string.
				var root any
				if json.Unmarshal(decoded, &root) == nil {
					v = normalizeMissing(part.variable, decoded, v)
				}
			}
		} else {
			var x any
			switch part.variable {
			case "aws.pipes.pipe-arn":
				x = p.Key.ARN()
			case "aws.pipes.pipe-name":
				x = p.Key.Name
			case "aws.pipes.source-arn":
				x = p.SourceARN
			case "aws.pipes.enrichment-arn":
				x = p.EnrichmentARN
			case "aws.pipes.target-arn":
				x = p.TargetARN
			case "aws.pipes.event.ingestion-time":
				x = now.UTC().Format(time.RFC3339Nano)
			case "aws.pipes.event":
				v = event
			case "aws.pipes.event.json":
				v = decoded
			}
			if v == nil {
				v, e = json.Marshal(x)
				if e != nil {
					return nil, e
				}
			}
		}
		if part.quoted {
			var str string
			if json.Unmarshal(v, &str) == nil {
				out.WriteString(str)
			} else {
				out.Write(bytes.ReplaceAll(v, []byte("\""), nil))
			}
		} else {
			out.Write(v)
		}
	}
	return out.Bytes(), nil
}

// A transformer variable uses the shared template primitive to distinguish an
// absent path from an actual empty object without maintaining another parser.
func normalizeMissing(path string, event, fallback []byte) []byte {
	p, e := inputtransform.Compile(inputtransform.Definition{Transformer: &inputtransform.Transformer{InputPathsMap: map[string]string{"v": path}, InputTemplate: "<v>"}})
	if e != nil {
		return fallback
	}
	v, e := p.Apply(event, inputtransform.Context{})
	if e == nil && len(v) == 0 {
		return []byte(`""`)
	}
	return fallback
}
func decodeEvent(event []byte) []byte {
	var root map[string]json.RawMessage
	if json.Unmarshal(event, &root) != nil {
		return event
	}
	changed := false
	for _, key := range []string{"body", "data", "key", "value"} {
		raw, ok := root[key]
		if !ok {
			continue
		}
		var text string
		if json.Unmarshal(raw, &text) != nil {
			continue
		}
		body := []byte(text)
		if key != "body" {
			v, e := base64.StdEncoding.DecodeString(text)
			if e != nil {
				continue
			}
			body = v
		}
		if json.Valid(body) {
			root[key] = body
			changed = true
		}
	}
	if !changed {
		return event
	}
	v, e := json.Marshal(root)
	if e != nil {
		return event
	}
	return v
}
func matches(filters []string, event []byte) (bool, error) {
	if len(filters) == 0 {
		return true, nil
	}
	body := decodeEvent(event)
	for _, f := range filters {
		p, e := eventpattern.Compile([]byte(f))
		if e != nil {
			return false, e
		}
		ok, e := p.Match(body)
		if e != nil {
			return false, e
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// ResolveParameter applies the shared EventBridge JSONPath primitive to dynamic
// target fields. Only a full path is dynamic; embedded path text stays literal.
func ResolveParameter(value string, event []byte) (string, error) {
	if !strings.HasPrefix(value, "$") {
		return value, nil
	}
	p, e := inputtransform.Compile(inputtransform.Definition{InputPath: &value})
	if e != nil {
		return "", e
	}
	b, e := p.Apply(decodeEvent(event), inputtransform.Context{})
	if e != nil {
		return "", e
	}
	var out string
	if json.Unmarshal(b, &out) == nil {
		return out, nil
	}
	if bytes.Equal(b, []byte("{}")) {
		return "", nil
	}
	return string(b), nil
}
func batchPayload(payloads [][]byte) ([]byte, error) {
	raw := make([]json.RawMessage, 0, len(payloads))
	for _, p := range payloads {
		if !json.Valid(p) {
			v, e := json.Marshal(string(p))
			if e != nil {
				return nil, e
			}
			raw = append(raw, v)
		} else {
			raw = append(raw, p)
		}
	}
	return json.Marshal(raw)
}
