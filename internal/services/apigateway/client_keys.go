package apigateway

import (
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/apigateway"
)

func clientKeyOutput(row ClientKeyRecord, includeValue, includeEmptyTags bool) *api.ApiKey {
	out := &api.ApiKey{
		Id: ptr(row.Key.ID), Name: (*api.String)(row.Name), Description: (*api.String)(row.Description),
		CustomerId: (*api.String)(row.CustomerID), Enabled: new(api.Boolean(row.Enabled)),
		CreatedDate: new(row.Created), LastUpdatedDate: new(row.Updated),
		StageKeys: make(api.ListOfString, len(row.StageKeys)), Tags: mapOut(row.Tags),
	}
	for i, stage := range row.StageKeys {
		out.StageKeys[i] = api.String(stage.ID + "/" + stage.Name)
	}
	if includeValue {
		out.Value = ptr(row.Value)
	}
	if includeEmptyTags && out.Tags == nil {
		out.Tags = api.MapOfStringToString{}
	}
	return out
}

func (s *Service) clientKey(r Reader, id, verb string) (ClientKeyRecord, error) {
	row, err := r.ClientKey(ClientKey{Scope: scopeFor(r.Context()), ID: id})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return row, err
	}
	if rejected := s.authorize(r, verb, "/apikeys/"+id, row.Tags); rejected != nil {
		return ClientKeyRecord{}, rejected
	}
	return row, err
}

func (s *Service) getAPIKey(tx Transaction, in *api.GetApiKeyRequest) (*api.ApiKey, error) {
	row, err := s.clientKey(tx, value(in.ApiKey), "GET")
	if err != nil {
		return nil, err
	}
	return clientKeyOutput(row, truth(in.IncludeValue), true), nil
}

func (s *Service) deleteAPIKey(tx Transaction, in *api.DeleteApiKeyRequest) (*api.Unit, error) {
	row, err := s.clientKey(tx, value(in.ApiKey), "DELETE")
	if err != nil {
		return nil, err
	}
	if err := tx.DeleteClientKey(row.Key); err != nil {
		return nil, err
	}
	return &api.Unit{}, nil
}

func validClientKeyName(name string) error {
	if utf8.RuneCountInString(name) > 1024 {
		return bad("API key name cannot exceed 1024 characters")
	}
	return nil
}

func validClientKeyValue(value string) error {
	if len(value) < 20 || len(value) > 128 {
		return bad("API key value must contain 20 through 128 alphanumeric characters")
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return bad("API key value must contain only alphanumeric characters")
		}
	}
	return nil
}

func clientKeyStage(r Reader, scope Scope, apiID, name string) (StageKey, error) {
	key := StageKey{APIKey: APIKey{Scope: scope, ID: apiID}, Name: name}
	if _, err := r.Stage(key); err != nil {
		return StageKey{}, err
	}
	return key, nil
}

func (s *Service) createAPIKey(tx Transaction, in *api.CreateApiKeyRequest) (*api.ApiKey, error) {
	if err := s.authorize(tx, "POST", "/apikeys", nil); err != nil {
		return nil, err
	}
	if err := validClientKeyName(value(in.Name)); err != nil {
		return nil, err
	}
	if in.CustomerId != nil && value(in.CustomerId) == "" {
		return nil, bad("Customer Id cannot be an empty string")
	}
	tags := mapIn(in.Tags)
	if err := validateTags(tags); err != nil {
		return nil, err
	}
	keyValue := value(in.Value)
	if in.Value == nil {
		keyValue = rand.Text()
	} else if err := validClientKeyValue(keyValue); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	if _, err := tx.ClientKeyByValue(scope, keyValue); err == nil {
		return nil, conflict("API key value already exists")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	stages := make([]StageKey, 0, len(in.StageKeys))
	for _, stage := range in.StageKeys {
		key, err := clientKeyStage(tx, scope, value(stage.RestApiId), value(stage.StageName))
		if err != nil {
			return nil, err
		}
		if !slices.Contains(stages, key) {
			stages = append(stages, key)
		}
	}
	// GenerateDistinctId is deprecated; both values keep ID separate from value.
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	row := ClientKeyRecord{Key: ClientKey{Scope: scope, ID: id}, Name: (*string)(in.Name), CustomerID: (*string)(in.CustomerId), Value: keyValue, Enabled: truth(in.Enabled), Created: now, Updated: now, Tags: tags, StageKeys: stages}
	if value(in.Description) != "" {
		row.Description = (*string)(in.Description)
	}
	if err := tx.PutClientKey(row); err != nil {
		return nil, err
	}
	return clientKeyOutput(row, true, false), nil
}

func (s *Service) getAPIKeys(tx Transaction, in *api.GetApiKeysRequest) (*api.ApiKeys, error) {
	if err := s.authorize(tx, "GET", "/apikeys", nil); err != nil {
		return nil, err
	}
	scope := scopeFor(tx.Context())
	rows, err := tx.ClientKeys(scope)
	if err != nil {
		return nil, err
	}
	rows = slices.DeleteFunc(rows, func(row ClientKeyRecord) bool {
		return !strings.HasPrefix(value(row.Name), value(in.NameQuery)) ||
			in.CustomerId != nil && value(row.CustomerID) != value(in.CustomerId)
	})
	collection := "apikeys/" + value(in.NameQuery) + "\x00" + value(in.CustomerId)
	rows, next, err := page(rows, scope, collection, in.Limit, in.Position, func(row ClientKeyRecord) string { return row.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.ApiKeys{Position: next, Items: make(api.ListOfApiKey, len(rows))}
	for i, row := range rows {
		out.Items[i] = *clientKeyOutput(row, truth(in.IncludeValues), false)
	}
	return out, nil
}

func (s *Service) updateAPIKey(tx Transaction, in *api.UpdateApiKeyRequest) (*api.ApiKey, error) {
	row, err := s.clientKey(tx, value(in.ApiKey), "PATCH")
	if err != nil {
		return nil, err
	}
	for _, patch := range in.PatchOperations {
		path := value(patch.Path)
		if path == "/stages" || strings.HasPrefix(path, "/stages/") {
			op, item, err := patchListChange(patch, "/stages")
			if err != nil {
				return nil, err
			}
			apiID, name, _ := strings.Cut(item, "/")
			key := StageKey{APIKey: APIKey{Scope: row.Key.Scope, ID: apiID}, Name: name}
			index := slices.Index(row.StageKeys, key)
			if op == "remove" {
				if index < 0 {
					return nil, bad("Stage association does not exist")
				}
				row.StageKeys = slices.Delete(row.StageKeys, index, index+1)
			} else {
				if _, err := clientKeyStage(tx, row.Key.Scope, apiID, name); err != nil {
					return nil, err
				}
				if index < 0 {
					row.StageKeys = append(row.StageKeys, key)
				}
			}
			continue
		}
		next := ""
		if err := replace(patch, &next); err != nil {
			return nil, err
		}
		switch path {
		case "/name":
			if err := validClientKeyName(next); err != nil {
				return nil, err
			}
			row.Name = &next
		case "/description":
			row.Description = nil
			if next != "" {
				row.Description = &next
			}
		case "/customerId":
			if next == "" {
				return nil, bad("Customer Id cannot be an empty string")
			}
			row.CustomerID = &next
		case "/enabled":
			row.Enabled = strings.EqualFold(next, "true")
		default:
			return nil, bad("Unsupported API key patch path: " + path)
		}
	}
	row.Updated = s.clock.Now()
	if err := tx.PutClientKey(row); err != nil {
		return nil, err
	}
	return clientKeyOutput(row, false, true), nil
}
