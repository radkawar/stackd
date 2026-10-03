package iam

import (
	"fmt"
	"strings"
	"unicode/utf8"

	iampolicy "stackd/iam/policy"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awswire"
)

// Simulation values are user-supplied hypothetical context, never verified
// authorization metadata. Retaining scalar/list types matters even when a list
// has only one element. This function owns and normalizes both returned maps.
func simulationContextEntries(entries iamapi.ContextEntryListType) (map[string][]string, map[string]string, *awswire.Error) {
	values := make(map[string][]string, len(entries))
	types := make(map[string]string, len(entries))
	for _, entry := range entries {
		// An entirely absent entry has no Query members on the AWS wire.
		if entry.ContextKeyName == nil && entry.ContextKeyType == nil && len(entry.ContextKeyValues) == 0 {
			continue
		}
		name := ""
		if entry.ContextKeyName != nil {
			name = string(*entry.ContextKeyName)
		}
		if name == "" {
			return nil, nil, invalidInput("ContextKeyName cannot be null or empty.")
		}
		if length := utf8.RuneCountInString(name); length < 5 || length > 256 {
			return nil, nil, &awswire.Error{Code: "ValidationError", Message: "ContextKeyName must contain between 5 and 256 characters.", StatusCode: 400}
		}
		key := strings.ToLower(name)
		if _, exists := values[key]; exists {
			return nil, nil, invalidInput("Duplicate context key: " + name + ".")
		}
		kind := "null"
		if entry.ContextKeyType != nil {
			kind = string(*entry.ContextKeyType)
		}
		switch iamapi.ContextKeyTypeEnum(kind) {
		case iamapi.ContextKeyTypeEnumSTRING, iamapi.ContextKeyTypeEnumSTRING_LIST,
			iamapi.ContextKeyTypeEnumNUMERIC, iamapi.ContextKeyTypeEnumNUMERIC_LIST,
			iamapi.ContextKeyTypeEnumBOOLEAN, iamapi.ContextKeyTypeEnumBOOLEAN_LIST,
			iamapi.ContextKeyTypeEnumIP, iamapi.ContextKeyTypeEnumIP_LIST,
			iamapi.ContextKeyTypeEnumBINARY, iamapi.ContextKeyTypeEnumBINARY_LIST,
			iamapi.ContextKeyTypeEnumDATE, iamapi.ContextKeyTypeEnumDATE_LIST:
		default:
			if entry.ContextKeyType != nil {
				return nil, nil, &awswire.Error{Code: "ValidationError", Message: "ContextKeyType must be one of string, stringList, numeric, numericList, boolean, booleanList, ip, ipList, binary, binaryList, date, dateList.", StatusCode: 400}
			}
			return nil, nil, invalidInput(fmt.Sprintf("Context key %s has invalid type %s.", name, kind))
		}
		if len(entry.ContextKeyValues) == 0 {
			return nil, nil, invalidInput("Context values for context key " + name + " cannot be null or empty.")
		}
		if !strings.HasSuffix(kind, "List") && len(entry.ContextKeyValues) != 1 {
			return nil, nil, invalidInput(fmt.Sprintf("Context key %s expected a single value, but received %d.", kind, len(entry.ContextKeyValues)))
		}
		normalized := make([]string, len(entry.ContextKeyValues))
		for index, value := range entry.ContextKeyValues {
			text, err := iampolicy.NormalizeSimulationContextValue(kind, string(value))
			if err != nil {
				format := map[string]string{"numeric": "numeric format", "date": "DateTime format", "ip": "IP address", "binary": "base-64 encoded binary format"}[strings.TrimSuffix(kind, "List")]
				return nil, nil, invalidInput(fmt.Sprintf("Invalid context value for key %s: expected %s.", name, format))
			}
			normalized[index] = text
		}
		values[key], types[key] = normalized, kind
	}
	return values, types, nil
}
