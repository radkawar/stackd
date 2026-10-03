package dynamodb

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	api "stackd/internal/awsapi/dynamodb"
)

// statementPage binds continuation to the actual table generation, statement
// bytes and ordered parameters. Limit and ConsistentRead may change between
// pages. The fixed-size query identity keeps large parameters out of the public
// token's 32768-byte budget; it is not authentication. Every page is authorized
// against current policies before the native engine executes it.
type statementPage struct {
	query  [sha256.Size]byte
	native *api.PartiQLNextToken
}

func newStatementPage(table *TableRecord, in *api.ExecuteStatementInput) (statementPage, error) {
	var page statementPage
	identity := struct {
		Table, ID, Statement string
		Parameters           api.PreparedStatementParameters
	}{table.Key.ARN(), value(table.Data.TableId), value(in.Statement), in.Parameters}
	hash := sha256.New()
	if err := json.NewEncoder(hash).Encode(identity); err != nil {
		return page, err
	}
	copy(page.query[:], hash.Sum(nil))
	if in.NextToken == nil {
		return page, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(*in.NextToken))
	if err != nil || len(raw) <= sha256.Size {
		return page, failure("ValidationException", "Invalid NextToken")
	}
	if !bytes.Equal(raw[:sha256.Size], page.query[:]) {
		return page, failure("ValidationException", "NextToken does not match request")
	}
	page.native = new(api.PartiQLNextToken(string(raw[sha256.Size:])))
	return page, nil
}

func (p statementPage) next(native *api.PartiQLNextToken) *api.PartiQLNextToken {
	if native == nil {
		return nil
	}
	data := make([]byte, sha256.Size+len(*native))
	copy(data, p.query[:])
	copy(data[sha256.Size:], string(*native))
	return new(api.PartiQLNextToken(base64.RawURLEncoding.EncodeToString(data)))
}
