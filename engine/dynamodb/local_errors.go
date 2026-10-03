package dynamodb

import (
	"encoding/json"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
)

// Local 3.3.1 omits the scalar DuplicateItemException suffix and classifies an
// INSERT duplicate as ValidationError inside a transaction.
func localPartiQLError(operation string, body []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	if operation == "ExecuteStatement" {
		var code string
		if err := json.Unmarshal(fields["__type"], &code); err != nil {
			return nil, err
		}
		if code == "DuplicateItem" || strings.HasSuffix(code, "#DuplicateItem") {
			fields["__type"], _ = json.Marshal(code + "Exception")
			return json.Marshal(fields)
		}
		return body, nil
	}
	if len(fields["CancellationReasons"]) == 0 {
		return body, nil
	}
	var reasons api.CancellationReasonList
	if err := json.Unmarshal(fields["CancellationReasons"], &reasons); err != nil {
		return nil, err
	}
	changed := false
	for i := range reasons {
		reason := &reasons[i]
		if reason.Code != nil && *reason.Code == "ValidationError" && reason.Message != nil && *reason.Message == "Duplicate primary key exists in table" {
			reason.Code = new(api.Code("DuplicateItem"))
			changed = true
		}
	}
	if !changed {
		return body, nil
	}
	encoded, err := json.Marshal(reasons)
	if err != nil {
		return nil, err
	}
	fields["CancellationReasons"] = encoded
	codes := make([]string, len(reasons))
	for i, reason := range reasons {
		if reason.Code != nil {
			codes[i] = string(*reason.Code)
		}
	}
	message, _ := json.Marshal("Transaction cancelled, please refer cancellation reasons for specific reasons [" + strings.Join(codes, ", ") + "]")
	for _, field := range []string{"message", "Message"} {
		if _, exists := fields[field]; exists {
			fields[field] = message
		}
	}
	return json.Marshal(fields)
}
