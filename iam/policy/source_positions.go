package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

type statementPosition struct{ start, end Position }

// statementPositions reads offsets from the original JSON. Searching for raw
// statement text would confuse repeated values or text nested in conditions.
func statementPositions(data []byte) ([]statementPosition, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, err
		}
		if key != "Statement" {
			continue
		}
		base := int(decoder.InputOffset()) - len(raw)
		// IAM points immediately after the opening delimiter. For arrays the
		// next statement begins at the preceding statement's end, before the
		// separating comma and whitespace. End points after the closing brace.
		offsets := [][2]int{{base + 1, base + len(raw)}}
		if len(raw) != 0 && raw[0] == '[' {
			offsets = nil
			array := json.NewDecoder(bytes.NewReader(raw))
			if _, err := array.Token(); err != nil {
				return nil, err
			}
			start := base + int(array.InputOffset())
			for array.More() {
				var statement json.RawMessage
				if err := array.Decode(&statement); err != nil {
					return nil, err
				}
				end := base + int(array.InputOffset())
				offsets = append(offsets, [2]int{start, end})
				start = end
			}
		}
		positions := make([]statementPosition, 0, len(offsets))
		cursor := sourceCursor{data: data, position: Position{Line: 1, Column: 1}}
		for _, span := range offsets {
			positions = append(positions, statementPosition{start: cursor.at(span[0]), end: cursor.at(span[1])})
		}
		return positions, nil
	}
	return nil, fmt.Errorf("statement is missing")
}

// Policy documents are immutable, so positions need only be computed once.
// Offsets arrive in source order, making this one pass even for large policies.
type sourceCursor struct {
	data           []byte
	offset         int
	position       Position
	carriageReturn bool
}

func (c *sourceCursor) at(offset int) Position {
	for c.offset < offset {
		r, width := utf8.DecodeRune(c.data[c.offset:])
		c.offset += width
		if r == '\r' || r == '\n' {
			if r == '\r' || !c.carriageReturn {
				c.position.Line++
			}
			c.position.Column = 1
		} else {
			c.position.Column++
		}
		c.carriageReturn = r == '\r'
	}
	return c.position
}
