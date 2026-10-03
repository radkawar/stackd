package inputtransform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type segment struct {
	text     string
	variable string
	quoted   bool
}

type template struct {
	segments  []segment
	object    bool
	multiline bool
}

func compileTemplate(source string) (template, error) {
	var result template
	var validation strings.Builder
	start := 0
	quoted, escaped, variableInString := false, false, false
	for i := 0; i < len(source); i++ {
		current := source[i]
		if current == '<' {
			end := strings.IndexByte(source[i+1:], '>')
			if end >= 0 {
				name := source[i+1 : i+1+end]
				if name == "aws.events.event" || name == "aws.events.event.json" {
					previous := strings.TrimRight(source[:i], " \r\n\t")
					if quoted || !strings.HasPrefix(strings.TrimSpace(source), "{") || !strings.HasSuffix(previous, ":") {
						return template{}, fmt.Errorf("reserved event variable must be a JSON object field value")
					}
				}
				result.segments = append(result.segments, segment{text: source[start:i]}, segment{variable: name, quoted: quoted})
				validation.WriteString(source[start:i])
				if quoted {
					validation.WriteString("variable")
					variableInString = true
				} else {
					validation.WriteString("null")
				}
				i += end + 1
				start = i + 1
				continue
			}
		}
		if escaped {
			escaped = false
			continue
		}
		if quoted && current == '\\' {
			escaped = true
			continue
		}
		if current == '"' {
			if quoted && variableInString && strings.HasPrefix(strings.TrimLeft(source[i+1:], " \r\n\t"), ":") {
				return template{}, fmt.Errorf("input template variable cannot be an object key")
			}
			quoted = !quoted
			variableInString = false
		}
	}
	result.segments = append(result.segments, segment{text: source[start:]})
	validation.WriteString(source[start:])
	var err error
	result.object, result.multiline, err = templateJSON([]byte(validation.String()))
	if err != nil {
		return template{}, fmt.Errorf("invalid input template: %w", err)
	}
	return result, nil
}

// templateJSON accepts one JSON value or the documented sequence of quoted text
// lines. The latter retains its line separators in the delivered message.
func templateJSON(source []byte) (object, multiline bool, err error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	count := 0
	allStrings := true
	for {
		var raw json.RawMessage
		err := decoder.Decode(&raw)
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, false, err
		}
		count++
		object = raw[0] == '{'
		allStrings = allStrings && raw[0] == '"'
	}
	if count == 0 || count > 1 && !allStrings {
		return false, false, fmt.Errorf("expected JSON or quoted text lines")
	}
	return object, count > 1, nil
}

func (p *Projection) render(root *value, context Context) ([]byte, error) {
	var out bytes.Buffer
	for _, segment := range p.template.segments {
		if segment.variable == "" {
			out.WriteString(segment.text)
			continue
		}
		var selected *value
		switch segment.variable {
		case "aws.events.rule-arn":
			selected = stringValue(context.RuleARN)
		case "aws.events.rule-name":
			selected = stringValue(context.RuleName)
		case "aws.events.event.ingestion-time":
			selected = stringValue(context.IngestionTime.UTC().Format("2006-01-02T15:04:05.000Z"))
		case "aws.events.event.json":
			selected = root
		case "aws.events.event":
			var err error
			selected, err = legacyEvent(root)
			if err != nil {
				return nil, err
			}
		default:
			path, exists := p.variables[segment.variable]
			if !exists {
				out.WriteString("<" + segment.variable + ">")
				continue
			}
			selected = path.selectValue(root)
		}
		if selected == nil {
			if p.template.object && !segment.quoted {
				out.WriteString(`""`)
			}
			continue
		}
		// Native object templates preserve JSON types. Text and root-array
		// templates instead interpolate unquoted strings and strip object keys'
		// and string values' quotes, including when this makes the result invalid.
		if p.template.object {
			raw := compact(selected.raw)
			if segment.quoted && selected.kind == '"' {
				raw = raw[1 : len(raw)-1]
			}
			out.Write(raw)
		} else if selected.kind == '"' {
			out.WriteString(selected.text)
		} else {
			out.WriteString(strings.ReplaceAll(string(compact(selected.raw)), `"`, ""))
		}
	}
	return out.Bytes(), nil
}

func compact(raw []byte) []byte {
	var out bytes.Buffer
	_ = json.Compact(&out, raw)
	return out.Bytes()
}

func stringValue(text string) *value {
	raw, _ := json.Marshal(text)
	return &value{kind: '"', text: text, raw: raw}
}

// The aws.events.event reserved variable uses AWS's legacy event header shape:
// detailType and epoch milliseconds, unlike aws.events.event.json's wire event.
func legacyEvent(root *value) (*value, error) {
	raw := []byte{'{'}
	for _, name := range []string{"id", "account", "detail-type", "time", "source", "region", "resources", "version"} {
		v := root.field(name)
		if v == nil {
			continue
		}
		value := v.raw
		switch name {
		case "detail-type":
			name = "detailType"
		case "time":
			timestamp, err := time.Parse(time.RFC3339Nano, v.text)
			if err != nil {
				return nil, fmt.Errorf("invalid event timestamp: %w", err)
			}
			value = []byte(strconv.FormatInt(timestamp.UnixMilli(), 10))
		}
		if len(raw) > 1 {
			raw = append(raw, ',')
		}
		raw = append(raw, '"')
		raw = append(raw, name...)
		raw = append(raw, '"', ':')
		raw = append(raw, value...)
	}
	return &value{kind: '{', raw: append(raw, '}')}, nil
}
