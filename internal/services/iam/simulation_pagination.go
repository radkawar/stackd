package iam

import (
	"encoding/base64"
	"encoding/json"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Simulation paginates the supplied action sequence, including duplicates. AWS
// accepts a continuation with changed actions, resources, policies and page size.
// Local markers preserve that ordinal behavior while retaining tenant scope.
type simulationContinuation struct {
	Partition string `json:"p"`
	Account   string `json:"a"`
	Operation string `json:"o"`
	Offset    int    `json:"i"`
}

func simulationPage(m awsctx.Metadata, operation string, marker *iamapi.MarkerType, maxItems *iamapi.MaxItemsType, count int) (int, int, *awswire.Error) {
	limit := 100
	if maxItems != nil {
		limit = int(*maxItems)
	}
	if limit < 1 || limit > 1000 {
		return 0, 0, invalidInput("MaxItems must be between 1 and 1000.")
	}
	start := 0
	if marker != nil {
		raw, err := base64.RawURLEncoding.DecodeString(string(*marker))
		var value simulationContinuation
		if err != nil || json.Unmarshal(raw, &value) != nil || value.Partition != m.Partition || value.Account != m.AccountID || value.Operation != operation || value.Offset < 1 {
			return 0, 0, invalidInput("Invalid marker for pagination.")
		}
		start = min(value.Offset, count)
	}
	return start, start + min(limit, count-start), nil
}

func simulationMarker(m awsctx.Metadata, operation string, offset int) string {
	data, _ := json.Marshal(simulationContinuation{Partition: m.Partition, Account: m.AccountID, Operation: operation, Offset: offset})
	return base64.RawURLEncoding.EncodeToString(data)
}
