package ecr

import (
	"encoding/json"
	"stackd/internal/authorization"
)

// ECR repository policies are implicitly scoped and may omit Resource. The
// shared IAM evaluator requires an explicit resource selector; only its private
// evaluation copy receives one, preserving the public policy document.
func repositoryPolicyDocument(text string) (string, []bool, error) {
	var doc map[string]json.RawMessage
	if json.Unmarshal([]byte(text), &doc) != nil {
		return "", nil, failure("InvalidParameterException", "Invalid repository policy JSON.")
	}
	raw := doc["Statement"]
	var statements []map[string]json.RawMessage
	single := len(raw) > 0 && raw[0] == '{'
	if single {
		var row map[string]json.RawMessage
		if json.Unmarshal(raw, &row) != nil {
			return "", nil, failure("InvalidParameterException", "Invalid policy statement.")
		}
		statements = append(statements, row)
	} else if json.Unmarshal(raw, &statements) != nil || len(statements) == 0 {
		return "", nil, failure("InvalidParameterException", "Policy statements are required.")
	}
	omitted := make([]bool, len(statements))
	for i, row := range statements {
		if _, ok := row["NotResource"]; ok {
			return "", nil, failure("InvalidParameterException", "Repository policies are implicitly scoped and do not accept NotResource.")
		}
		resource, exists := row["Resource"]
		omitted[i] = !exists
		if !exists {
			row["Resource"] = json.RawMessage(`"*"`)
		} else {
			var value string
			if json.Unmarshal(resource, &value) != nil || value != "*" {
				return "", nil, failure("InvalidParameterException", "Repository policies must omit Resource or use '*'.")
			}
		}
	}
	var encoded []byte
	if single {
		encoded, _ = json.Marshal(statements[0])
	} else {
		encoded, _ = json.Marshal(statements)
	}
	doc["Statement"] = encoded
	encoded, _ = json.Marshal(doc)
	return string(encoded), omitted, nil
}
func (s *Service) bindRepositoryPolicy(tx Transaction, text string) (authorization.BoundPolicy, error) {
	normalized, _, err := repositoryPolicyDocument(text)
	if err != nil {
		return authorization.BoundPolicy{}, err
	}
	bound, err := s.bindPolicy(tx, normalized)
	if err != nil {
		return authorization.BoundPolicy{}, err
	}
	bound.Document = text
	return bound, nil
}
func (s *Service) renderRepositoryPolicy(tx Reader, bound authorization.BoundPolicy) (string, error) {
	normalized, omitted, err := repositoryPolicyDocument(bound.Document)
	if err != nil {
		return "", err
	}
	bound.Document = normalized
	rendered, err := s.renderPolicy(tx, bound)
	if err != nil {
		return "", err
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal([]byte(rendered), &doc); err != nil {
		return "", err
	}
	raw := doc["Statement"]
	single := len(raw) > 0 && raw[0] == '{'
	var rows []map[string]json.RawMessage
	if single {
		var row map[string]json.RawMessage
		if err = json.Unmarshal(raw, &row); err != nil {
			return "", err
		}
		rows = append(rows, row)
	} else if err = json.Unmarshal(raw, &rows); err != nil {
		return "", err
	}
	for i, missing := range omitted {
		if missing && i < len(rows) {
			delete(rows[i], "Resource")
		}
	}
	if single {
		doc["Statement"], err = json.Marshal(rows[0])
	} else {
		doc["Statement"], err = json.Marshal(rows)
	}
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(doc)
	return string(encoded), err
}
