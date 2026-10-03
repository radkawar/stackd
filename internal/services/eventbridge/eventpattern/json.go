package eventpattern

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type valueKind uint8

const (
	nullValue valueKind = iota
	stringValue
	numberValue
	boolValue
	objectValue
	arrayValue
)

type value struct {
	kind    valueKind
	text    string
	members []member
	items   []value
}

type member struct {
	name  string
	value value
}

func parse(data []byte) (value, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	root, err := readValue(decoder)
	if err != nil {
		return value{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return value{}, fmt.Errorf("unexpected data after JSON value")
	}
	if root.kind != objectValue {
		return value{}, fmt.Errorf("JSON must be an object")
	}
	return root, nil
}

func readValue(decoder *json.Decoder) (value, error) {
	token, err := decoder.Token()
	if err != nil {
		return value{}, err
	}
	switch token := token.(type) {
	case nil:
		return value{kind: nullValue}, nil
	case string:
		return value{kind: stringValue, text: token}, nil
	case json.Number:
		return value{kind: numberValue, text: string(token)}, nil
	case bool:
		if token {
			return value{kind: boolValue, text: "true"}, nil
		}
		return value{kind: boolValue, text: "false"}, nil
	case json.Delim:
		out := value{kind: arrayValue}
		if token == '{' {
			out.kind = objectValue
		}
		for decoder.More() {
			var key string
			if out.kind == objectValue {
				name, err := decoder.Token()
				if err != nil {
					return value{}, err
				}
				key = name.(string)
			}
			child, err := readValue(decoder)
			if err != nil {
				return value{}, err
			}
			if out.kind == objectValue {
				// Keep every member: pattern compilation validates duplicates
				// before replacing leaf rules, while events retain both values.
				out.members = append(out.members, member{name: key, value: child})
			} else {
				out.items = append(out.items, child)
			}
		}
		if _, err := decoder.Token(); err != nil {
			return value{}, err
		}
		return out, nil
	default:
		return value{}, fmt.Errorf("unexpected JSON token")
	}
}
