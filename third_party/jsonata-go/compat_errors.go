package jsonata

import (
	"fmt"
	"regexp"
)

// ErrType identifies the reason for a legacy-compatible evaluation error.
type ErrType uint

// Legacy evaluation error types retained for source compatibility with
// blues/jsonata-go v1.5.4.
const (
	ErrNonIntegerLHS ErrType = iota
	ErrNonIntegerRHS
	ErrNonNumberLHS
	ErrNonNumberRHS
	ErrNonComparableLHS
	ErrNonComparableRHS
	ErrTypeMismatch
	ErrNonCallable
	ErrNonCallableApply
	ErrNonCallablePartial
	ErrNumberInf
	ErrNumberNaN
	ErrMaxRangeItems
	ErrIllegalKey
	ErrDuplicateKey
	ErrClone
	ErrIllegalUpdate
	ErrIllegalDelete
	ErrNonSortable
	ErrSortMismatch
)

var legacyErrorMessages = map[ErrType]string{
	ErrNonIntegerLHS:      `left side of the "{{value}}" operator must evaluate to an integer`,
	ErrNonIntegerRHS:      `right side of the "{{value}}" operator must evaluate to an integer`,
	ErrNonNumberLHS:       `left side of the "{{value}}" operator must evaluate to a number`,
	ErrNonNumberRHS:       `right side of the "{{value}}" operator must evaluate to a number`,
	ErrNonComparableLHS:   `left side of the "{{value}}" operator must evaluate to a number or string`,
	ErrNonComparableRHS:   `right side of the "{{value}}" operator must evaluate to a number or string`,
	ErrTypeMismatch:       `both sides of the "{{value}}" operator must have the same type`,
	ErrNonCallable:        `cannot call non-function {{token}}`,
	ErrNonCallableApply:   `cannot use function application with non-function {{token}}`,
	ErrNonCallablePartial: `cannot partially apply non-function {{token}}`,
	ErrNumberInf:          `result of the "{{value}}" operator is out of range`,
	ErrNumberNaN:          `result of the "{{value}}" operator is not a valid number`,
	ErrMaxRangeItems:      `range operator has too many items`,
	ErrIllegalKey:         `object key {{token}} does not evaluate to a string`,
	ErrDuplicateKey:       `multiple object keys evaluate to the value "{{value}}"`,
	ErrClone:              `object transformation: cannot make a copy of the object`,
	ErrIllegalUpdate:      `the insert/update clause of an object transformation must evaluate to an object`,
	ErrIllegalDelete:      `the delete clause of an object transformation must evaluate to an array of strings`,
	ErrNonSortable:        `expressions in a sort term must evaluate to strings or numbers`,
	ErrSortMismatch:       `expressions in a sort term must have the same type`,
}

var legacyErrorField = regexp.MustCompile(`{{(token|value)}}`)

// EvalError preserves the exported legacy error shape. New code should prefer
// Error, which exposes JSONata 2.2 error codes and source positions.
type EvalError struct {
	Type  ErrType
	Token string
	Value string
}

func (e EvalError) Error() string {
	message := legacyErrorMessages[e.Type]
	if message == "" {
		return fmt.Sprintf("EvalError: unknown error type %d", e.Type)
	}
	return legacyErrorField.ReplaceAllStringFunc(message, func(field string) string {
		switch field {
		case "{{token}}":
			return e.Token
		case "{{value}}":
			return e.Value
		default:
			return field
		}
	})
}

// ArgCountError reports a legacy extension call with the wrong arity.
type ArgCountError struct {
	Func     string
	Expected int
	Received int
}

func (e ArgCountError) Error() string {
	return fmt.Sprintf("function %q takes %d argument(s), got %d", e.Func, e.Expected, e.Received)
}

// ArgTypeError reports a legacy extension argument that did not match the Go
// function signature. Which is one-based.
type ArgTypeError struct {
	Func  string
	Which int
}

func (e ArgTypeError) Error() string {
	return fmt.Sprintf("argument %d of function %q does not match function signature", e.Which, e.Func)
}
