package logs

import (
	"encoding/base64"
	"encoding/json"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
)

type pageToken struct {
	Query     string      `json:"q"`
	Direction string      `json:"d"`
	Name      string      `json:"n,omitempty"`
	GroupName string      `json:"g,omitempty"`
	Cursor    EventCursor `json:"c"`
	HasCursor bool        `json:"h,omitempty"`
	Issued    int64       `json:"i"`
}

func queryIdentity(parts ...any) string { data, _ := json.Marshal(parts); return string(data) }
func (s *Service) decodeToken(text, query string) (pageToken, *awswire.Error) {
	if text == "" {
		return pageToken{Query: query, Issued: s.clock.Now().UnixMilli()}, nil
	}
	var t pageToken
	b, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || json.Unmarshal(b, &t) != nil || t.Query != query || t.Issued > s.clock.Now().UnixMilli() || s.clock.Now().UnixMilli()-t.Issued >= 86400000 {
		return t, invalid("The nextToken is invalid or has expired.")
	}
	return t, nil
}
func encodeToken(t pageToken) *api.NextToken {
	b, _ := json.Marshal(t)
	return new(api.NextToken(base64.RawURLEncoding.EncodeToString(b)))
}
func pageLimit[T ~int32](p *T, def, maxValue int) (int, *awswire.Error) {
	if p == nil {
		return def, nil
	}
	n := int(*p)
	if n < 1 || n > maxValue {
		return 0, invalid("The limit is outside the allowed range.")
	}
	return n, nil
}
