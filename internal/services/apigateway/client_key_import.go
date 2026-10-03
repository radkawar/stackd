package apigateway

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"

	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/awswire"
)

// retainedFailure is a client rejection whose earlier successful mutations
// survive. The transaction adapter commits its failure event with those effects.
// Native ImportApiKeys exhibits this behavior when failOnWarnings is true.
type retainedFailure struct{ cause *awswire.Error }

func (e *retainedFailure) Error() string { return e.cause.Error() }
func (e *retainedFailure) Unwrap() error { return e.cause }

func (s *Service) importAPIKeys(tx Transaction, in *api.ImportApiKeysRequest) (*api.ApiKeyIds, error) {
	if err := s.authorize(tx, "POST", "/apikeys", nil); err != nil {
		return nil, err
	}
	if value(in.Format) != "csv" {
		return nil, bad("API key import format must be csv")
	}
	reader := csv.NewReader(bytes.NewReader(in.Body))
	header, err := reader.Read()
	if err != nil {
		return nil, bad("Invalid API key CSV header")
	}
	columns := make(map[string]int, len(header))
	for i, name := range header {
		columns[strings.ToLower(name)] = i
	}
	for _, name := range []string{"name", "key"} {
		if _, ok := columns[name]; !ok {
			return nil, bad("Missing required column '" + name + "'")
		}
	}
	out := &api.ApiKeyIds{Ids: api.ListOfString{}, Warnings: api.ListOfString{}}
	for number := 1; ; number++ {
		fields, err := reader.Read()
		// AWS also accepts single-quoted lists in UsagePlanIds. encoding/csv
		// treats their commas as separators; reassemble only that bound column.
		if index, present := columns["usageplanids"]; present && errors.Is(err, csv.ErrFieldCount) && len(fields) > len(header) {
			last := index + len(fields) - len(header)
			if strings.HasPrefix(fields[index], "'") && strings.HasSuffix(fields[last], "'") {
				fields[index] = strings.Join(fields[index:last+1], ",")
				copy(fields[index+1:], fields[last+1:])
				fields = fields[:len(header)]
				err = nil
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			out.Warnings = append(out.Warnings, api.String(fmt.Sprintf("Skipped invalid record: %d. %v", number, err)))
			continue
		}
		column := func(name string) string {
			if index, ok := columns[name]; ok {
				return fields[index]
			}
			return ""
		}
		name, keyValue := column("name"), column("key")
		if err := validClientKeyName(name); err != nil {
			out.Warnings = append(out.Warnings, api.String(fmt.Sprintf("Skipped invalid record: %d. %s", number, err)))
			continue
		}
		if err := validClientKeyValue(keyValue); err != nil {
			out.Warnings = append(out.Warnings, api.String(fmt.Sprintf("Skipped invalid record: %d. %s", number, err)))
			continue
		}
		scope := scopeFor(tx.Context())
		row, err := tx.ClientKeyByValue(scope, keyValue)
		if errors.Is(err, ErrNotFound) {
			id, err := newID()
			if err != nil {
				return nil, err
			}
			row = ClientKeyRecord{Key: ClientKey{Scope: scope, ID: id}, Value: keyValue}
		} else if err != nil {
			return nil, err
		}
		row.Name = &name
		row.Description = nil
		if description := column("description"); description != "" {
			row.Description = &description
		}
		row.Enabled = true
		if _, present := columns["enabled"]; present {
			row.Enabled = strings.EqualFold(column("enabled"), "true")
		}
		// Native overwrite preserves the identifier, but replaces both dates.
		now := s.clock.Now()
		row.Created, row.Updated = now, now
		if err := tx.PutClientKey(row); err != nil {
			return nil, err
		}
		for _, id := range strings.Split(strings.Trim(column("usageplanids"), "'"), ",") {
			if id == "" {
				continue
			}
			plan, err := tx.UsagePlan(PlanKey{Scope: scope, ID: id})
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if _, err := tx.UsagePlanMembership(plan.Key, row.Key.ID); err == nil {
				continue
			} else if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			if err := s.attachUsagePlanKey(tx, plan, row); err != nil {
				var rejected *awswire.Error
				if !errors.As(err, &rejected) {
					return nil, err
				}
				out.Warnings = append(out.Warnings, api.String(fmt.Sprintf("Skipped usage plan association for record: %d. %s", number, rejected.Message)))
			}
		}
		out.Ids = append(out.Ids, api.String(row.Key.ID))
	}
	if truth(in.FailOnWarnings) && len(out.Warnings) != 0 {
		return nil, &retainedFailure{cause: bad("Warnings found during import:\n\t" + strings.Join(stringsIn(out.Warnings), "\n\t"))}
	}
	return out, nil
}
