package apigateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	api "stackd/internal/awsapi/apigateway"
	"strings"
)

func apiOutput(v APIRecord) *api.RestApi {
	return &api.RestApi{Id: ptr(v.Key.ID), Name: ptr(v.Name), Description: optional(v.Description), Version: optional(v.Version), CreatedDate: new(v.Created), RootResourceId: ptr(v.RootResourceID), DisableExecuteApiEndpoint: new(api.Boolean(v.Disabled)), ApiKeySource: new(api.ApiKeySourceType(v.APIKeySource)), EndpointConfiguration: &api.EndpointConfiguration{Types: api.ListOfEndpointType{api.EndpointTypeREGIONAL}, IpAddressType: new(api.IpAddressType("ipv4"))}, SecurityPolicy: new(api.SecurityPolicy("TLS_1_0")), ApiStatus: new(api.ApiStatusAVAILABLE), Tags: mapOut(v.Tags), BinaryMediaTypes: stringsOut(v.BinaryMediaTypes)}
}
func (s *Service) createRestAPI(tx Transaction, in *api.CreateRestApiRequest) (*api.RestApi, error) {
	if err := s.authorize(tx, "POST", "/restapis", nil); err != nil {
		return nil, err
	}
	if strings.TrimSpace(value(in.Name)) == "" || len(value(in.Name)) > 1024 {
		return nil, bad("Invalid API name")
	}
	// Edge/private endpoints, compression, resource policies and cloning require
	// distinct provisioning owners.
	if in.EndpointConfiguration != nil {
		if len(in.EndpointConfiguration.Types) != 1 || in.EndpointConfiguration.Types[0] != api.EndpointTypeREGIONAL || len(in.EndpointConfiguration.VpcEndpointIds) != 0 {
			return nil, unsupported("only REGIONAL endpoints are supported")
		}
		if t := value(in.EndpointConfiguration.IpAddressType); t != "" && t != "ipv4" {
			return nil, unsupported("dualstack endpoints")
		}
	}
	if in.MinimumCompressionSize != nil || value(in.Policy) != "" || value(in.CloneFrom) != "" || value(in.EndpointAccessMode) != "" {
		return nil, unsupported("compression, resource policies, cloning or endpoint access mode")
	}
	keySource := value(in.ApiKeySource)
	if keySource == "" {
		keySource = "HEADER"
	}
	if keySource != "HEADER" && keySource != "AUTHORIZER" {
		return nil, bad("API key source must be HEADER or AUTHORIZER")
	}
	if t := value(in.SecurityPolicy); t != "" && t != "TLS_1_0" {
		return nil, unsupported("custom TLS security policy")
	}
	if err := validateBinaryMediaTypes(stringsIn(in.BinaryMediaTypes)); err != nil {
		return nil, err
	}
	tags := mapIn(in.Tags)
	if err := validateTags(tags); err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	if _, e := tx.Owner(id); !errors.Is(e, ErrNotFound) {
		if e != nil {
			return nil, e
		}
		return nil, conflict("API identifier already exists")
	}
	root, err := newID()
	if err != nil {
		return nil, err
	}
	row := APIRecord{Key: APIKey{Scope: scopeFor(tx.Context()), ID: id}, Name: value(in.Name), Description: value(in.Description), Version: value(in.Version), RootResourceID: root, Created: s.clock.Now(), Disabled: truth(in.DisableExecuteApiEndpoint), Tags: tags}
	row.APIKeySource = keySource
	row.BinaryMediaTypes = stringsIn(in.BinaryMediaTypes)
	if err := tx.PutAPI(row); err != nil {
		return nil, err
	}
	if err := tx.PutResource(ResourceRecord{Key: ResourceKey{APIKey: row.Key, ResourceID: root}, Path: "/"}); err != nil {
		return nil, err
	}
	return apiOutput(row), nil
}
func (s *Service) getRestAPI(tx Transaction, in *api.GetRestApiRequest) (*api.RestApi, error) {
	row, err := s.api(tx, value(in.RestApiId), "GET", "")
	if err != nil {
		return nil, err
	}
	return apiOutput(row), nil
}
func (s *Service) getRestAPIs(tx Transaction, in *api.GetRestApisRequest) (*api.RestApis, error) {
	if err := s.authorize(tx, "GET", "/restapis", nil); err != nil {
		return nil, err
	}
	rows, err := tx.APIs(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, scopeFor(tx.Context()), "apis", in.Limit, in.Position, func(v APIRecord) string { return v.Key.ID })
	if err != nil {
		return nil, err
	}
	out := &api.RestApis{Items: api.ListOfRestApi{}, Position: next}
	for _, v := range rows {
		out.Items = append(out.Items, *apiOutput(v))
	}
	return out, nil
}
func (s *Service) deleteRestAPI(tx Transaction, in *api.DeleteRestApiRequest) (*api.Unit, error) {
	row, err := s.api(tx, value(in.RestApiId), "DELETE", "")
	if err != nil {
		return nil, err
	}
	return &api.Unit{}, tx.DeleteAPI(row.Key)
}
func (s *Service) updateRestAPI(tx Transaction, in *api.UpdateRestApiRequest) (*api.RestApi, error) {
	row, err := s.api(tx, value(in.RestApiId), "PATCH", "")
	if err != nil {
		return nil, err
	}
	for _, p := range in.PatchOperations {
		path := value(p.Path)
		if strings.HasPrefix(path, "/binaryMediaTypes/") {
			if err := patchBinaryMediaTypes(&row, p); err != nil {
				return nil, err
			}
			continue
		}
		switch path {
		case "/name":
			if err := replace(p, &row.Name); err != nil {
				return nil, err
			}
			if strings.TrimSpace(row.Name) == "" || len(row.Name) > 1024 {
				return nil, bad("Invalid API name")
			}
		case "/description":
			if err := patchString(p, &row.Description, "add", "replace", "remove"); err != nil {
				return nil, err
			}
		case "/version":
			if err := patchString(p, &row.Version, "add", "replace", "remove"); err != nil {
				return nil, err
			}
		case "/disableExecuteApiEndpoint":
			if err := patchBool(p, &row.Disabled); err != nil {
				return nil, err
			}
		case "/apiKeySource":
			if err := replace(p, &row.APIKeySource); err != nil {
				return nil, err
			}
			if row.APIKeySource != "HEADER" && row.APIKeySource != "AUTHORIZER" {
				return nil, bad("API key source must be HEADER or AUTHORIZER")
			}
		case "/endpointConfiguration/types/REGIONAL":
			v := "REGIONAL"
			if err := replace(p, &v); err != nil {
				return nil, err
			}
			if v != "REGIONAL" {
				return nil, unsupported("edge/private endpoint provisioning")
			}
		case "/endpointConfiguration/ipAddressType":
			v := "ipv4"
			if err := replace(p, &v); err != nil {
				return nil, err
			}
			if v != "ipv4" {
				return nil, unsupported("dualstack endpoints")
			}
		case "/minimumCompressionSize":
			if value(p.Op) != "replace" || p.Value != nil {
				return nil, unsupported("compression")
			}
		default:
			return nil, unsupported("REST API patch path " + path)
		}
	}
	if err := tx.PutAPI(row); err != nil {
		return nil, err
	}
	return apiOutput(row), nil
}

type pageToken struct {
	Scope             Scope
	Collection, After string
}

// Continuations bind the retained owner and collection, and remain stable when
// page size changes or a preceding resource is deleted.
func page[T any](rows []T, scope Scope, collection string, limit *api.NullableInteger, position *api.String, id func(T) string) ([]T, *api.String, error) {
	n := 25
	if limit != nil {
		n = int(*limit)
	}
	if n < 1 || n > 500 {
		return nil, nil, bad("Invalid limit; expected 1 through 500")
	}
	after := ""
	if position != nil {
		data, err := base64.RawURLEncoding.DecodeString(string(*position))
		var token pageToken
		if err != nil || json.Unmarshal(data, &token) != nil || token.Scope != scope || token.Collection != collection || token.After == "" {
			return nil, nil, bad("Invalid position")
		}
		after = token.After
	}
	start := 0
	for start < len(rows) && id(rows[start]) <= after {
		start++
	}
	rows = rows[start:]
	if len(rows) <= n {
		return rows, nil, nil
	}
	data, err := json.Marshal(pageToken{Scope: scope, Collection: collection, After: id(rows[n-1])})
	if err != nil {
		return nil, nil, err
	}
	return rows[:n], ptr(base64.RawURLEncoding.EncodeToString(data)), nil
}
