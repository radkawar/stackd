package inputtransform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type member struct {
	name  string
	value *value
}
type value struct {
	raw     []byte
	kind    byte
	text    string
	members []member
	items   []*value
}

func parseEvent(data []byte) (*value, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	root, err := readValue(decoder, data)
	if err != nil {
		return nil, fmt.Errorf("invalid event JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after event JSON")
	}
	return root, nil
}

func readValue(decoder *json.Decoder, data []byte) (*value, error) {
	start := decoder.InputOffset()
	for start < int64(len(data)) && bytes.ContainsRune([]byte(" \r\n\t,:"), rune(data[start])) {
		start++
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	out := &value{}
	switch token := token.(type) {
	case json.Delim:
		out.kind = byte(token)
		for decoder.More() {
			name := ""
			if token == '{' {
				key, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				name = key.(string)
			}
			child, err := readValue(decoder, data)
			if err != nil {
				return nil, err
			}
			if token == '{' {
				out.members = append(out.members, member{name, child})
			} else {
				out.items = append(out.items, child)
			}
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
	case string:
		out.kind = '"'
		out.text = token
	case json.Number:
		out.kind = 'n'
		out.text = string(token)
	case bool:
		out.kind = 'b'
		if token {
			out.text = "true"
		} else {
			out.text = "false"
		}
	case nil:
		out.kind = '0'
		out.text = "null"
	}
	out.raw = bytes.TrimSpace(data[start:decoder.InputOffset()])
	return out, nil
}

func (v *value) field(name string) *value {
	for i := len(v.members) - 1; i >= 0; i-- {
		if v.members[i].name == name {
			return v.members[i].value
		}
	}
	return nil
}

func arrayValue(values []*value) *value {
	raw := []byte{'['}
	for i, v := range values {
		if i != 0 {
			raw = append(raw, ',')
		}
		raw = append(raw, v.raw...)
	}
	raw = append(raw, ']')
	return &value{kind: '[', raw: raw, items: values}
}
