package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"time"
)

type valueKind uint8

const (
	stringKind valueKind = iota
	arnKind
	numericKind
	dateKind
	boolKind
	binaryKind
	ipKind
	nullKind
)

type comparison uint8

const (
	equal comparison = iota
	equalFold
	like
	less
	lessEqual
	greater
	greaterEqual
)

type quantifier uint8

const (
	singleValue quantifier = iota
	allValues
	anyValue
)

type operator struct {
	kind       valueKind
	comparison comparison
	negated    bool
	ifExists   bool
	quantifier quantifier
}

type condition struct {
	name      string
	key       string
	sourceKey string
	op        operator
	values    []conditionValue
}

type conditionValue struct {
	template *valueTemplate
	pattern  []patternToken
	absent   bool
	invalid  bool
	text     string
	number   *big.Rat
	date     time.Time
	boolean  bool
	bytes    []byte
	prefix   netip.Prefix
	address  netip.Addr
}

// ValidateStoredConditions checks an IAM stored policy's Condition object.
// The caller validates the enclosing document and enables variables only for
// version 2012-10-17. IAM storage rejects empty value arrays and malformed
// literals; STS session parsing has its separate acceptance contract.
func ValidateStoredConditions(data []byte, variables bool) error {
	conditions, err := parseConditions(data, identityDocument, variables)
	if err != nil {
		return err
	}
	for _, c := range conditions {
		if len(c.values) == 0 {
			return fmt.Errorf("%w: %s/%s requires at least one value", ErrInvalidPolicy, c.name, c.key)
		}
	}
	return nil
}

func parseConditions(raw json.RawMessage, kind documentKind, variables bool) ([]condition, error) {
	obj, err := object(raw)
	if err != nil || len(obj) == 0 && kind != sessionDocument {
		return nil, fmt.Errorf("%w: Condition must be a nonempty object", ErrInvalidPolicy)
	}
	var conditions []condition
	for _, name := range sortedKeys(obj) {
		op, err := parseOperator(name)
		if err != nil {
			return nil, err
		}
		keys, err := object(obj[name])
		if err != nil || len(keys) == 0 {
			return nil, fmt.Errorf("%w: %s must contain condition keys", ErrInvalidPolicy, name)
		}
		for _, key := range sortedKeys(keys) {
			if key == "" {
				return nil, fmt.Errorf("%w: condition key must not be empty", ErrInvalidPolicy)
			}
			if variables && strings.Contains(key, "${") {
				return nil, fmt.Errorf("%w: policy variables cannot appear in condition keys", ErrInvalidPolicy)
			}
			values, err := scalarOrArray(keys[key])
			if err != nil {
				return nil, fmt.Errorf("%w: %s/%s requires a scalar or array of values", ErrInvalidPolicy, name, key)
			}
			c := condition{name: name, key: strings.ToLower(key), sourceKey: key, op: op}
			for _, rawValue := range values {
				value, err := conditionScalar(rawValue)
				if err != nil {
					return nil, fmt.Errorf("%w: %s/%s: %v", ErrInvalidPolicy, name, key, err)
				}
				if variables && strings.Contains(value, "${") {
					if op.kind != stringKind && op.kind != arnKind {
						return nil, fmt.Errorf("%w: policy variables require a String or ARN condition operator", ErrInvalidPolicy)
					}
					template, err := compileTemplate(value, true)
					if err != nil {
						return nil, err
					}
					c.values = append(c.values, conditionValue{text: value, template: &template})
					continue
				}
				compiled, err := compileValue(op.kind, value, true)
				if err != nil {
					// STS and simulation defer different literal failures to the
					// comparison; neither changes IAM's storage validation.
					allowInvalid := kind == sessionDocument && op.kind != binaryKind || kind.simulation() && op.kind == ipKind
					if !allowInvalid {
						return nil, fmt.Errorf("%w: %s/%s: %v", ErrInvalidPolicy, name, key, err)
					}
					compiled.invalid = true
				}
				c.values = append(c.values, compiled)
			}
			conditions = append(conditions, c)
		}
	}
	return conditions, nil
}

func parseOperator(name string) (operator, error) {
	original := name
	var op operator
	switch {
	case strings.HasPrefix(name, "ForAllValues:"):
		op.quantifier = allValues
		name = strings.TrimPrefix(name, "ForAllValues:")
	case strings.HasPrefix(name, "ForAnyValue:"):
		op.quantifier = anyValue
		name = strings.TrimPrefix(name, "ForAnyValue:")
	}
	if strings.HasSuffix(name, "IfExists") {
		op.ifExists = true
		name = strings.TrimSuffix(name, "IfExists")
	}
	switch name {
	case "StringEquals", "StringNotEquals":
		op.kind, op.comparison = stringKind, equal
	case "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase":
		op.kind, op.comparison = stringKind, equalFold
	case "StringLike", "StringNotLike":
		op.kind, op.comparison = stringKind, like
	case "ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike":
		op.kind, op.comparison = arnKind, like
	case "NumericEquals", "NumericNotEquals":
		op.kind, op.comparison = numericKind, equal
	case "NumericLessThan":
		op.kind, op.comparison = numericKind, less
	case "NumericLessThanEquals":
		op.kind, op.comparison = numericKind, lessEqual
	case "NumericGreaterThan":
		op.kind, op.comparison = numericKind, greater
	case "NumericGreaterThanEquals":
		op.kind, op.comparison = numericKind, greaterEqual
	case "DateEquals", "DateNotEquals":
		op.kind, op.comparison = dateKind, equal
	case "DateLessThan":
		op.kind, op.comparison = dateKind, less
	case "DateLessThanEquals":
		op.kind, op.comparison = dateKind, lessEqual
	case "DateGreaterThan":
		op.kind, op.comparison = dateKind, greater
	case "DateGreaterThanEquals":
		op.kind, op.comparison = dateKind, greaterEqual
	case "Bool":
		op.kind = boolKind
	case "BinaryEquals":
		op.kind = binaryKind
	case "IpAddress", "NotIpAddress":
		op.kind = ipKind
	case "Null":
		op.kind = nullKind
		if op.ifExists || op.quantifier != singleValue {
			return op, fmt.Errorf("%w: Null does not accept set operators or IfExists", ErrInvalidPolicy)
		}
	default:
		return op, fmt.Errorf("%w: condition operator %q", ErrUnsupported, original)
	}
	op.negated = strings.Contains(name, "Not")
	return op, nil
}

func conditionScalar(raw json.RawMessage) (string, error) {
	if len(raw) > 0 && raw[0] == '"' {
		return stringValue(raw)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return "", err
	}
	switch v := value.(type) {
	case json.Number:
		return v.String(), nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	default:
		return "", fmt.Errorf("condition values must be strings, numbers, or booleans")
	}
}

func compileValue(kind valueKind, text string, policyValue bool) (conditionValue, error) {
	v := conditionValue{text: text}
	var err error
	switch kind {
	case numericKind:
		v.number, err = parseNumber(text)
	case dateKind:
		v.date, err = conditionDate(text)
		v.date = v.date.Truncate(time.Millisecond)
	case boolKind, nullKind:
		v.boolean = strings.EqualFold(text, "true")
	case binaryKind:
		v.bytes, err = base64.StdEncoding.Strict().DecodeString(text)
	case ipKind:
		if policyValue {
			v.prefix, err = conditionPrefix(text)
		} else {
			v.address, err = conditionAddress(text)
		}
	case arnKind:
		parts := strings.SplitN(text, ":", 6)
		if !(policyValue && text == "*") && (len(parts) != 6 || parts[0] != "arn") {
			err = fmt.Errorf("expected complete ARN")
		}
	}
	return v, err
}

func parseNumber(text string) (*big.Rat, error) {
	text, err := conditionNumber(text)
	if err != nil {
		return nil, err
	}
	// Rat preserves integer precision beyond float64's 53-bit mantissa. Its
	// parser also bounds exponent size, preventing unchecked huge exponents.
	v, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, fmt.Errorf("number is out of range")
	}
	return v, nil
}

func parseDate(text string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04Z07:00", time.DateOnly, "2006-01", "2006"} {
		if value, err := time.Parse(layout, text); err == nil {
			return value, nil
		}
	}
	number, err := parseNumber(text)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected ISO 8601 date or epoch seconds")
	}
	seconds, remainder := new(big.Int), new(big.Int)
	seconds.QuoRem(number.Num(), number.Denom(), remainder)
	if !seconds.IsInt64() {
		return time.Time{}, fmt.Errorf("epoch seconds are out of range")
	}
	remainder.Mul(remainder, big.NewInt(1_000_000_000))
	nanos := remainder.Quo(remainder, number.Denom()).Int64()
	return time.Unix(seconds.Int64(), nanos).UTC(), nil
}
