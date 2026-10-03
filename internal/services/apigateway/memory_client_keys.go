package apigateway

import (
	"cmp"
	"maps"
	"slices"
)

type clientKeyValue struct {
	Scope
	Value string
}

func cloneClientKey(row ClientKeyRecord) ClientKeyRecord {
	if row.Name != nil {
		row.Name = new(*row.Name)
	}
	if row.Description != nil {
		row.Description = new(*row.Description)
	}
	if row.CustomerID != nil {
		row.CustomerID = new(*row.CustomerID)
	}
	row.Tags = maps.Clone(row.Tags)
	row.StageKeys = slices.Clone(row.StageKeys)
	return row
}

func (r memoryReader) ClientKey(key ClientKey) (ClientKeyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ClientKeyRecord{}, err
	}
	row, ok := r.s.clientKeys[key]
	if !ok {
		return ClientKeyRecord{}, ErrNotFound
	}
	return cloneClientKey(row), nil
}

func (r memoryReader) ClientKeyByValue(scope Scope, value string) (ClientKeyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ClientKeyRecord{}, err
	}
	key, ok := r.s.clientKeyValues[clientKeyValue{Scope: scope, Value: value}]
	if !ok {
		return ClientKeyRecord{}, ErrNotFound
	}
	return cloneClientKey(r.s.clientKeys[key]), nil
}

func (r memoryReader) ClientKeys(scope Scope) ([]ClientKeyRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]ClientKeyRecord, 0)
	for key, row := range r.s.clientKeys {
		if key.Scope == scope {
			rows = append(rows, cloneClientKey(row))
		}
	}
	slices.SortFunc(rows, func(a, b ClientKeyRecord) int { return cmp.Compare(a.Key.ID, b.Key.ID) })
	return rows, nil
}

func (w memoryWriter) PutClientKey(row ClientKeyRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.clientKeys[row.Key] = cloneClientKey(row)
	// Key values are immutable; admission owns scoped uniqueness.
	w.s.clientKeyValues[clientKeyValue{Scope: row.Key.Scope, Value: row.Value}] = row.Key
	return nil
}

func (w memoryWriter) DeleteClientKey(key ClientKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if row, ok := w.s.clientKeys[key]; ok {
		delete(w.s.clientKeyValues, clientKeyValue{Scope: key.Scope, Value: row.Value})
		delete(w.s.clientKeys, key)
	}
	delete(w.s.usageMemberships, key)
	delete(w.s.usageDays, key)
	return nil
}
