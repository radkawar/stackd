package jsonata

import (
	"errors"
	"fmt"
)

// ErrUndefined is returned when an expression produces JSONata's empty
// sequence. It is identical in value and text to blues/jsonata-go's sentinel.
var ErrUndefined = errors.New("no results found")

// Error is a structured JSONata syntax or evaluation error. Position is a
// one-based UTF-16 code-unit offset into the expression. Value retains the
// JSONata value supplied by the reference diagnostic, including null, bool,
// and number values.
type Error struct {
	Code     string
	Token    string
	Value    any
	Position int
	Message  string
	cause    error
}

// JSONataError is the descriptive name for Error; both names are supported.
type JSONataError = Error

// JSONataCode lets conformance and embedding code inspect an error without
// depending on the concrete package type.
func (e Error) JSONataCode() string { return e.Code }

func (e Error) Unwrap() error { return e.cause }

// As preserves the legacy EvalError inspection surface for codes whose
// meaning is unambiguous in the modern JSONata diagnostics.
func (e Error) As(target any) bool {
	typ, ok := legacyErrorType(e.Code)
	if !ok {
		return false
	}
	legacy := EvalError{Type: typ, Token: e.Token, Value: legacyErrorValue(e.Value)}
	switch value := target.(type) {
	case *EvalError:
		if value == nil {
			return false
		}
		*value = legacy
	case **EvalError:
		if value == nil {
			return false
		}
		*value = &legacy
	default:
		return false
	}
	return true
}

func legacyErrorValue(value any) string {
	if value == nil {
		return "null"
	}
	return fmt.Sprint(value)
}

func legacyErrorType(code string) (ErrType, bool) {
	switch code {
	case "T2003":
		return ErrNonIntegerLHS, true
	case "T2004":
		return ErrNonIntegerRHS, true
	case "T2001":
		return ErrNonNumberLHS, true
	case "T2002":
		return ErrNonNumberRHS, true
	case "T1005", "T1006":
		return ErrNonCallable, true
	case "T1007", "T1008":
		return ErrNonCallablePartial, true
	case "T2006":
		return ErrNonCallableApply, true
	case "T2007":
		return ErrSortMismatch, true
	case "T2008":
		return ErrNonSortable, true
	case "D1001":
		return ErrNumberInf, true
	case "D2014":
		return ErrMaxRangeItems, true
	case "T1003":
		return ErrIllegalKey, true
	case "D1009":
		return ErrDuplicateKey, true
	case "T2011":
		return ErrIllegalUpdate, true
	case "T2012":
		return ErrIllegalDelete, true
	default:
		return 0, false
	}
}

func (e Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Code != "" {
		return fmt.Sprintf("jsonata %s", e.Code)
	}
	return "jsonata error"
}
