package identitystore

import (
	"errors"
	"slices"
	api "stackd/internal/awsapi/identitystore"
)

func (s *Service) registerGroups() {
	register(s, "CreateGroup", s.createGroup)
	register(s, "DescribeGroup", s.describeGroup)
	register(s, "DeleteGroup", s.deleteGroup)
	register(s, "ListGroups", s.listGroups)
	register(s, "GetGroupId", s.getGroupID)
	register(s, "UpdateGroup", s.updateGroup)
}
func (s *Service) createGroup(tx Transaction, in *api.CreateGroupInput) (*api.CreateGroupOutput, error) {
	store := value(in.IdentityStoreId)
	if e := s.admit(tx, "CreateGroup", store, "", "", ""); e != nil {
		return nil, e
	}
	name := value(in.DisplayName)
	if name == "" || reservedName(name) {
		return nil, bad("DisplayName is required and must not be reserved.")
	}
	if _, e := tx.GroupByName(store, name); e == nil {
		return nil, conflict("DisplayName already exists.")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	id, e := resourceID(store)
	if e != nil {
		return nil, e
	}
	if e := tx.PutGroup(Group{StoreID: store, ID: id, DisplayName: name, Description: value(in.Description)}); e != nil {
		return nil, e
	}
	return &api.CreateGroupOutput{IdentityStoreId: in.IdentityStoreId, GroupId: new(api.ResourceId(id))}, nil
}
func apiGroup(v Group) api.Group {
	return api.Group{IdentityStoreId: new(api.IdentityStoreId(v.StoreID)), GroupId: new(api.ResourceId(v.ID)), DisplayName: new(api.GroupDisplayName(v.DisplayName)), Description: text(v.Description)}
}
func (s *Service) describeGroup(tx Transaction, in *api.DescribeGroupInput) (*api.DescribeGroupOutput, error) {
	store, id := value(in.IdentityStoreId), value(in.GroupId)
	if e := s.admit(tx, "DescribeGroup", store, "", id, ""); e != nil {
		return nil, e
	}
	g, e := tx.Group(Key{store, id})
	if e != nil {
		return nil, e
	}
	out := api.DescribeGroupOutput(apiGroup(g))
	return &out, nil
}
func (s *Service) deleteGroup(tx Transaction, in *api.DeleteGroupInput) (*api.DeleteGroupOutput, error) {
	store, id := value(in.IdentityStoreId), value(in.GroupId)
	if e := s.admit(tx, "DeleteGroup", store, "", id, ""); e != nil {
		return nil, e
	}
	if _, e := tx.Group(Key{store, id}); e != nil {
		return nil, e
	}
	return &api.DeleteGroupOutput{}, tx.DeleteGroup(Key{store, id})
}
func (s *Service) listGroups(tx Transaction, in *api.ListGroupsInput) (*api.ListGroupsOutput, error) {
	store := value(in.IdentityStoreId)
	if e := s.admit(tx, "ListGroups", store, "", "*", ""); e != nil {
		return nil, e
	}
	name, e := filterName(in.Filters, "DisplayName")
	if e != nil {
		return nil, e
	}
	rows, e := tx.Groups(store)
	if e != nil {
		return nil, e
	}
	if name != "" {
		rows = slices.DeleteFunc(rows, func(v Group) bool { return v.DisplayName != name })
	}
	rows, next, e := page(rows, queryKey("ListGroups", store, name), in.MaxResults, in.NextToken, func(v Group) string { return v.ID })
	if e != nil {
		return nil, e
	}
	out := &api.ListGroupsOutput{Groups: api.Groups{}, NextToken: next}
	for _, v := range rows {
		out.Groups = append(out.Groups, apiGroup(v))
	}
	return out, nil
}
func (s *Service) getGroupID(tx Transaction, in *api.GetGroupIdInput) (*api.GetGroupIdOutput, error) {
	store := value(in.IdentityStoreId)
	if e := s.admit(tx, "GetGroupId", store, "", "", ""); e != nil {
		return nil, e
	}
	name, e := uniqueName(in.AlternateIdentifier, "DisplayName")
	if e != nil {
		return nil, e
	}
	g, e := tx.GroupByName(store, name)
	if e != nil {
		return nil, e
	}
	if e := s.admit(tx, "GetGroupId", store, "", g.ID, ""); e != nil {
		return nil, e
	}
	return &api.GetGroupIdOutput{IdentityStoreId: in.IdentityStoreId, GroupId: new(api.ResourceId(g.ID))}, nil
}
