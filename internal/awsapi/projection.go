package awsapi

import (
	"encoding/json"
	"reflect"

	"stackd/internal/awscatalog"
)

// FieldMode selects a service-owned public projection, not a wire encoding.
type FieldMode uint8

const (
	ProjectField FieldMode = iota
	OmitField
	RedactField
	RedactValueField
	IncludeField
	JSONField
)

// FieldProjection changes one modeled field in an audit document.
// RedactField preserves lists and empties objects; RedactValueField replaces the
// entire value with AWS's hidden-value marker by default.
// IncludeField retains a modeled sensitive field when native evidence logs it.
// JSONField likewise retains valid JSON strings as documents; invalid input stays
// a string so observing a rejected policy does not itself fail.
type FieldProjection struct {
	Mode       FieldMode
	Name       string
	TimeLayout string
	// Redaction overrides the native hidden-value marker for redaction modes.
	Redaction string
}

// DocumentProjection selects public fields from generated shapes before their
// values are serialized. Sensitive fields are omitted unless explicitly included,
// parsed as JSON or redacted; blobs can only be redacted, never copied. Sources
// must also exclude unmarked secrets: Smithy alone does not describe CloudTrail.
//
// Paths use Smithy member names separated by dots. Collection indices and user
// map keys are not path components. User map keys are never renamed.
type DocumentProjection struct {
	PreserveNames bool
	Fields        map[string]FieldProjection
}

type documentPosition struct {
	projection       *DocumentProjection
	path             string
	rule             FieldProjection
	sensitive        bool
	response         bool
	sdk              bool
	sdkOptimized     bool
	sdkInvokePayload bool
}

func (p documentPosition) member(member awscatalog.Member) documentPosition {
	if p.projection == nil {
		return documentPosition{response: p.response, sdk: p.sdk, sdkOptimized: p.sdkOptimized, sdkInvokePayload: p.sdkInvokePayload && member.HTTPPayload}
	}
	next := documentPosition{projection: p.projection, sensitive: member.Sensitive, response: p.response, sdk: p.sdk, sdkOptimized: p.sdkOptimized, sdkInvokePayload: p.sdkInvokePayload && member.HTTPPayload}
	if len(p.projection.Fields) != 0 {
		next.path = member.Name
		if p.path != "" {
			next.path = p.path + "." + member.Name
		}
		next.rule = p.projection.Fields[next.path]
	}
	return next
}

func (p documentPosition) name(member awscatalog.Member) string {
	if p.sdk {
		return sdkMemberName(member.Name)
	}
	name := memberJSONName(member)
	if p.projection == nil {
		return name
	}
	if p.rule.Name != "" {
		return p.rule.Name
	}
	if !p.projection.PreserveNames && name != "" && name[0] >= 'A' && name[0] <= 'Z' {
		return string(name[0]+('a'-'A')) + name[1:]
	}
	return name
}

func (p documentPosition) replacement(shape awscatalog.Shape, value reflect.Value) (json.RawMessage, bool) {
	if p.projection == nil {
		return nil, false
	}
	switch p.rule.Mode {
	case OmitField:
		return nil, true
	case RedactField:
		switch shape.Kind {
		case "list", "set": // Elements retain this rule during recursion.
			return nil, false
		case "structure", "union", "map":
			return json.RawMessage("{}"), true
		}
		fallthrough
	case RedactValueField:
		if p.rule.Redaction != "" {
			marker, _ := json.Marshal(p.rule.Redaction)
			return marker, true
		}
		return json.RawMessage(`"HIDDEN_DUE_TO_SECURITY_REASONS"`), true
	}
	if shape.Kind == "blob" || ((p.sensitive || shape.Sensitive) && p.rule.Mode != IncludeField && p.rule.Mode != JSONField) {
		return nil, true
	}
	if p.rule.Mode == JSONField && value.Kind() == reflect.String {
		text := value.String()
		if json.Valid([]byte(text)) {
			return json.RawMessage(text), true
		}
	}
	return nil, false
}
