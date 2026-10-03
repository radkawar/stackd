package dynamodb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/dynamodb"
	"stackd/internal/messageattribute"
)

// DynamoDB Local compares transaction attribute encodings, while AWS compares
// numeric values and unordered sets. Copy only values whose native encoding
// changes; caller-owned input remains intact for audit and error reporting.
func transactionAttributes[M ~map[K]api.AttributeValue, K ~string](in M) (M, bool) {
	out := in
	changed := false
	for key, value := range in {
		normalized, different := transactionAttribute(value)
		if !different {
			continue
		}
		if !changed {
			out = maps.Clone(in)
			changed = true
		}
		out[key] = normalized
	}
	return out, changed
}

func transactionValues[S ~[]api.AttributeValue](in S) (S, bool) {
	out := in
	changed := false
	for i, value := range in {
		normalized, different := transactionAttribute(value)
		if !different {
			continue
		}
		if !changed {
			out = slices.Clone(in)
			changed = true
		}
		out[i] = normalized
	}
	return out, changed
}

func transactionAttribute(in api.AttributeValue) (api.AttributeValue, bool) {
	out := in
	changed := false
	if in.N != nil {
		if number := transactionNumber(*in.N); number != *in.N {
			out.N, changed = &number, true
		}
	}
	if in.NS != nil {
		numbersChanged := false
		for i, number := range in.NS {
			normalized := transactionNumber(number)
			if normalized == number {
				continue
			}
			if !numbersChanged {
				out.NS = slices.Clone(in.NS)
				numbersChanged = true
			}
			out.NS[i] = normalized
		}
		if !slices.IsSorted(out.NS) {
			if !numbersChanged {
				out.NS = slices.Clone(in.NS)
				numbersChanged = true
			}
			slices.Sort(out.NS)
		}
		changed = changed || numbersChanged
	}
	if !slices.IsSorted(in.SS) {
		out.SS = slices.Clone(in.SS)
		slices.Sort(out.SS)
		changed = true
	}
	compareBinary := func(a, b api.BinaryAttributeValue) int { return bytes.Compare(a, b) }
	if !slices.IsSortedFunc(in.BS, compareBinary) {
		out.BS = slices.Clone(in.BS)
		slices.SortFunc(out.BS, compareBinary)
		changed = true
	}
	var different bool
	out.M, different = transactionAttributes(in.M)
	changed = changed || different
	out.L, different = transactionValues(in.L)
	return out, changed || different
}

func transactionNumber(in api.NumberAttributeValue) api.NumberAttributeValue {
	number, err := messageattribute.ParseNumber(string(in), -130)
	if err != nil {
		// Preserve invalid input for the native operation's validation error.
		return in
	}
	return api.NumberAttributeValue(number.String())
}

// Local forgets rejected transaction parameters. Retain only the normalized
// request identity needed to enforce AWS's canceled-token reuse contract.
// Response modes are compared separately; this is not an execution journal.
func transactionRequestIdentity(in any) (string, error) {
	var request any
	switch in := in.(type) {
	case *api.TransactWriteItemsInput:
		request = &api.TransactWriteItemsInput{TransactItems: in.TransactItems}
	case *api.ExecuteTransactionInput:
		statements := in.TransactStatements
		changed := false
		for i, statement := range in.TransactStatements {
			text := strings.TrimSpace(value(statement.Statement))
			if text == value(statement.Statement) {
				continue
			}
			if !changed {
				statements = slices.Clone(statements)
				changed = true
			}
			statements[i].Statement = new(api.PartiQLStatement(text))
		}
		request = &api.ExecuteTransactionInput{TransactStatements: statements}
	default:
		return "", fmt.Errorf("unsupported DynamoDB transaction identity %T", in)
	}
	encoded, err := json.Marshal(request)
	return string(encoded), err
}
