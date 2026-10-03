package policy

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// NormalizeSimulationContextValue validates a declared IAM simulation value and
// returns its comparison spelling. Decimal scale is preserved, dates include
// milliseconds, boolean parsing is case-insensitive, and IP/binary spellings
// remain intact. A list type validates each element with the same rules.
func NormalizeSimulationContextValue(kind, value string) (string, error) {
	switch strings.TrimSuffix(kind, "List") {
	case "string":
		return value, nil
	case "boolean":
		return strconv.FormatBool(strings.EqualFold(value, "true")), nil
	case "numeric":
		return conditionNumber(value)
	case "date":
		date, err := conditionDate(value)
		if err != nil {
			return "", err
		}
		return date.UTC().Format("2006-01-02T15:04:05.000Z07:00"), nil
	case "ip":
		if _, err := conditionAddress(value); err != nil {
			return "", err
		}
		return value, nil
	case "binary":
		decoded, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
			return "", fmt.Errorf("%w: expected base-64 encoded binary format", ErrInvalidRequest)
		}
		return value, nil
	default:
		return "", fmt.Errorf("%w: unknown simulation context type %q", ErrInvalidRequest, kind)
	}
}
