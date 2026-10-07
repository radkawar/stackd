package apigatewayv2

import (
	"errors"
	api "stackd/internal/awsapi/apigatewayv2"
	"strings"
)

func mappingOutput(v MappingRecord) api.ApiMapping {
	out := api.ApiMapping{}
	text(&out.ApiId, v.APIID)
	text(&out.ApiMappingId, v.Key.ID)
	text(&out.ApiMappingKey, v.Path)
	text(&out.Stage, v.Stage)
	return out
}
func (s *Service) validateMapping(tx Transaction, v MappingRecord) error {
	if v.APIID == "" || v.Stage == "" {
		return bad("ApiId and Stage are required")
	}
	if len(v.Path) > 300 || strings.HasPrefix(v.Path, "/") || strings.HasSuffix(v.Path, "/") || strings.Contains(v.Path, "//") {
		return bad("Invalid ApiMappingKey")
	}
	for _, c := range v.Path {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("$-_.+!*'()/", c)) {
			return bad("Invalid ApiMappingKey")
		}
	}
	owner, e := tx.API(APIKey{v.Key.Scope, v.APIID})
	if e != nil {
		return e
	}
	if _, e = tx.Stage(ResourceKey{owner.Key, v.Stage}); e != nil {
		return e
	}
	if owner.ProtocolType == "WEBSOCKET" && strings.Contains(v.Path, "/") {
		return bad("WebSocket mappings cannot contain multiple path segments")
	}
	rows, e := tx.Mappings(v.Key.DomainKey)
	if e != nil {
		return e
	}
	for _, row := range rows {
		if row.Key == v.Key {
			continue
		}
		if row.Path == v.Path {
			return failure("ConflictException", "ApiMappingKey already exists", 409)
		}
		other, e := tx.API(APIKey{row.Key.Scope, row.APIID})
		if errors.Is(e, ErrNotFound) {
			continue
		}
		if e != nil {
			return e
		}
		if other.ProtocolType != owner.ProtocolType {
			return bad("A custom domain may only map APIs of the same protocol")
		}
	}
	return nil
}
func (s *Service) createMapping(tx Transaction, in *api.CreateApiMappingInput) (*api.CreateApiMappingOutput, error) {
	d, e := s.ownedDomain(tx, "POST", value(in.DomainName), "/apimappings")
	if e != nil {
		return nil, e
	}
	owner, bound := ResourceOwnerFromContext(tx.Context())
	if bound {
		rows, e := tx.Mappings(d.Key)
		if e != nil {
			return nil, e
		}
		for _, v := range rows {
			if v.Owner == owner {
				return new(api.CreateApiMappingOutput(mappingOutput(v))), nil
			}
		}
	}
	id, e := controlID()
	if e != nil {
		return nil, e
	}
	v := MappingRecord{Key: MappingKey{d.Key, id}, Owner: owner, APIID: value(in.ApiId), Stage: value(in.Stage), Path: value(in.ApiMappingKey)}
	if e = s.validateMapping(tx, v); e != nil {
		return nil, e
	}
	if e = tx.PutMapping(v); e != nil {
		return nil, e
	}
	return new(api.CreateApiMappingOutput(mappingOutput(v))), nil
}
func (s *Service) ownedMapping(tx Transaction, method, name, id string) (MappingRecord, error) {
	d, e := s.ownedDomain(tx, method, name, "/apimappings/"+id)
	if e != nil {
		return MappingRecord{}, e
	}
	return tx.Mapping(MappingKey{d.Key, id})
}
func (s *Service) getMapping(tx Transaction, in *api.GetApiMappingInput) (*api.GetApiMappingOutput, error) {
	v, e := s.ownedMapping(tx, "GET", value(in.DomainName), value(in.ApiMappingId))
	if e != nil {
		return nil, e
	}
	return new(api.GetApiMappingOutput(mappingOutput(v))), nil
}
func (s *Service) getMappings(tx Transaction, in *api.GetApiMappingsInput) (*api.GetApiMappingsOutput, error) {
	d, e := s.ownedDomain(tx, "GET", value(in.DomainName), "/apimappings")
	if e != nil {
		return nil, e
	}
	rows, e := tx.Mappings(d.Key)
	if e != nil {
		return nil, e
	}
	rows, next, e := page(rows, value(in.MaxResults), value(in.NextToken), pageBinding(tx, "/domainnames/"+d.Key.Name+"/apimappings"), func(v MappingRecord) string { return v.Key.ID })
	if e != nil {
		return nil, e
	}
	out := &api.GetApiMappingsOutput{}
	for _, v := range rows {
		out.Items = append(out.Items, mappingOutput(v))
	}
	if out.Items == nil {
		out.Items = []api.ApiMapping{}
	}
	if next != nil {
		text(&out.NextToken, *next)
	}
	return out, nil
}
func (s *Service) updateMapping(tx Transaction, in *api.UpdateApiMappingInput) (*api.UpdateApiMappingOutput, error) {
	v, e := s.ownedMapping(tx, "PATCH", value(in.DomainName), value(in.ApiMappingId))
	if e != nil {
		return nil, e
	}
	if e = domainOwner(tx, v.Owner); e != nil {
		return nil, e
	}
	v.APIID = value(in.ApiId)
	if in.Stage != nil {
		v.Stage = value(in.Stage)
	}
	if in.ApiMappingKey != nil {
		v.Path = value(in.ApiMappingKey)
	}
	if e = s.validateMapping(tx, v); e != nil {
		return nil, e
	}
	if e = tx.PutMapping(v); e != nil {
		return nil, e
	}
	return new(api.UpdateApiMappingOutput(mappingOutput(v))), nil
}
func (s *Service) deleteMapping(tx Transaction, in *api.DeleteApiMappingInput) (*api.DeleteApiMappingOutput, error) {
	v, e := s.ownedMapping(tx, "DELETE", value(in.DomainName), value(in.ApiMappingId))
	if e != nil {
		return nil, e
	}
	if e = domainOwner(tx, v.Owner); e != nil {
		return nil, e
	}
	if e = tx.DeleteMapping(v.Key); e != nil {
		return nil, e
	}
	return &api.DeleteApiMappingOutput{}, nil
}
