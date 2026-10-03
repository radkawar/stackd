package apigateway

import (
	"regexp"
	"slices"
	api "stackd/internal/awsapi/apigateway"
	"strings"
)

var literalPart = regexp.MustCompile(`^[a-zA-Z0-9._:-]+$`)
var parameterPart = regexp.MustCompile(`^\{[a-zA-Z0-9_]+\+?\}$`)

func variablePart(s string) bool { return parameterPart.MatchString(s) }
func resourceOutput(v ResourceRecord) *api.Resource {
	return &api.Resource{Id: ptr(v.Key.ResourceID), ParentId: optional(v.ParentID), PathPart: optional(v.PathPart), Path: ptr(v.Path)}
}
func resourcePlacement(rows []ResourceRecord, row ResourceRecord) (string, error) {
	if !literalPart.MatchString(row.PathPart) && !parameterPart.MatchString(row.PathPart) {
		return "", bad("Invalid resource path part")
	}
	var parent *ResourceRecord
	for i := range rows {
		v := &rows[i]
		if v.Key.ResourceID == row.ParentID {
			parent = v
		}
		if v.Key.ResourceID == row.Key.ResourceID {
			continue
		}
		if v.ParentID == row.ParentID && (v.PathPart == row.PathPart || (variablePart(v.PathPart) && variablePart(row.PathPart))) {
			return "", conflict("A sibling resource with this path part or a variable already exists")
		}
	}
	if parent == nil {
		return "", ErrNotFound
	}
	if strings.HasSuffix(parent.PathPart, "+}") {
		return "", bad("Cannot create a child of a greedy resource")
	}
	if parent.Key.ResourceID == row.Key.ResourceID {
		return "", bad("Resource cannot be its own parent")
	}
	old := ""
	for _, v := range rows {
		if v.Key == row.Key {
			old = v.Path
			break
		}
	}
	if old != "" && strings.HasPrefix(parent.Path, old+"/") {
		return "", bad("Resource cannot be moved beneath itself")
	}
	return strings.TrimRight(parent.Path, "/") + "/" + row.PathPart, nil
}
func (s *Service) createResource(tx Transaction, in *api.CreateResourceRequest) (*api.Resource, error) {
	owner, err := s.api(tx, value(in.RestApiId), "POST", "/resources/"+value(in.ParentId))
	if err != nil {
		return nil, err
	}
	rows, err := tx.Resources(owner.Key)
	if err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	row := ResourceRecord{Key: ResourceKey{APIKey: owner.Key, ResourceID: id}, ParentID: value(in.ParentId), PathPart: value(in.PathPart)}
	row.Path, err = resourcePlacement(rows, row)
	if err != nil {
		return nil, err
	}
	if err := tx.PutResource(row); err != nil {
		return nil, err
	}
	return resourceOutput(row), nil
}
func resourceMethods(r Reader, row ResourceRecord, embed bool) (*api.Resource, error) {
	out := resourceOutput(row)
	methods, err := r.Methods(row.Key.APIKey)
	if err != nil {
		return nil, err
	}
	for _, m := range methods {
		if m.Key.ResourceKey != row.Key {
			continue
		}
		if out.ResourceMethods == nil {
			out.ResourceMethods = api.MapOfMethod{}
		}
		v := api.Method{}
		if embed {
			result, err := methodOutput(r, m)
			if err != nil {
				return nil, err
			}
			v = *result
		}
		out.ResourceMethods[api.String(m.Key.HTTPMethod)] = v
	}
	return out, nil
}
func validEmbed(in api.ListOfString, allowed string) (bool, error) {
	for _, v := range in {
		if string(v) != allowed {
			return false, bad("Invalid embed parameter")
		}
	}
	return len(in) > 0, nil
}
func (s *Service) getResource(tx Transaction, in *api.GetResourceRequest) (*api.Resource, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/resources/"+value(in.ResourceId))
	if err != nil {
		return nil, err
	}
	embed, err := validEmbed(in.Embed, "methods")
	if err != nil {
		return nil, err
	}
	row, err := tx.Resource(ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)})
	if err != nil {
		return nil, err
	}
	return resourceMethods(tx, row, embed)
}
func (s *Service) getResources(tx Transaction, in *api.GetResourcesRequest) (*api.Resources, error) {
	owner, err := s.api(tx, value(in.RestApiId), "GET", "/resources")
	if err != nil {
		return nil, err
	}
	embed, err := validEmbed(in.Embed, "methods")
	if err != nil {
		return nil, err
	}
	rows, err := tx.Resources(owner.Key)
	if err != nil {
		return nil, err
	}
	rows, next, err := page(rows, owner.Key.Scope, "resources/"+owner.Key.ID, in.Limit, in.Position, func(v ResourceRecord) string { return v.Key.ResourceID })
	if err != nil {
		return nil, err
	}
	out := &api.Resources{Items: api.ListOfResource{}, Position: next}
	for _, v := range rows {
		item, err := resourceMethods(tx, v, embed)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, *item)
	}
	return out, nil
}
func (s *Service) updateResource(tx Transaction, in *api.UpdateResourceRequest) (*api.Resource, error) {
	owner, err := s.api(tx, value(in.RestApiId), "PATCH", "/resources/"+value(in.ResourceId))
	if err != nil {
		return nil, err
	}
	row, err := tx.Resource(ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)})
	if err != nil {
		return nil, err
	}
	if row.ParentID == "" {
		return nil, bad("The root resource cannot be updated")
	}
	oldPath := row.Path
	for _, p := range in.PatchOperations {
		switch value(p.Path) {
		case "/pathPart":
			err = replace(p, &row.PathPart)
		case "/parentId":
			err = replace(p, &row.ParentID)
		default:
			err = bad("Invalid resource patch path")
		}
		if err != nil {
			return nil, err
		}
	}
	rows, err := tx.Resources(owner.Key)
	if err != nil {
		return nil, err
	}
	row.Path, err = resourcePlacement(rows, row)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(row.PathPart, "+}") {
		for _, v := range rows {
			if v.ParentID == row.Key.ResourceID {
				return nil, bad("A greedy resource cannot have children")
			}
		}
	}
	if err := tx.PutResource(row); err != nil {
		return nil, err
	}
	for _, v := range rows {
		if strings.HasPrefix(v.Path, oldPath+"/") {
			v.Path = row.Path + strings.TrimPrefix(v.Path, oldPath)
			if err := tx.PutResource(v); err != nil {
				return nil, err
			}
		}
	}
	return resourceMethods(tx, row, true)
}
func (s *Service) deleteResource(tx Transaction, in *api.DeleteResourceRequest) (*api.Unit, error) {
	owner, err := s.api(tx, value(in.RestApiId), "DELETE", "/resources/"+value(in.ResourceId))
	if err != nil {
		return nil, err
	}
	row, err := tx.Resource(ResourceKey{APIKey: owner.Key, ResourceID: value(in.ResourceId)})
	if err != nil {
		return nil, err
	}
	if row.ParentID == "" {
		return nil, bad("The root resource cannot be deleted")
	}
	rows, err := tx.Resources(owner.Key)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rows, func(a, b ResourceRecord) int { return len(b.Path) - len(a.Path) })
	for _, v := range rows {
		if v.Key == row.Key || strings.HasPrefix(v.Path, row.Path+"/") {
			if err := tx.DeleteResource(v.Key); err != nil {
				return nil, err
			}
		}
	}
	return &api.Unit{}, nil
}
