package lambda

import (
	"bytes"
	"encoding/json"
)

const sourceEventLimit = 6 * 1024 * 1024

func sourceJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}
