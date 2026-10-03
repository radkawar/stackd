package identitystore

import (
	"errors"
	api "stackd/internal/awsapi/identitystore"
)

func (s *Service) registerMemberships() {
	register(s, "CreateGroupMembership", s.createMembership)
	register(s, "DeleteGroupMembership", s.deleteMembership)
	register(s, "DescribeGroupMembership", s.describeMembership)
	register(s, "GetGroupMembershipId", s.getMembershipID)
	register(s, "ListGroupMemberships", s.listMemberships)
	register(s, "ListGroupMembershipsForMember", s.listMembershipsForMember)
	register(s, "IsMemberInGroups", s.isMemberInGroups)
}
func (s *Service) createMembership(tx Transaction, in *api.CreateGroupMembershipInput) (*api.CreateGroupMembershipOutput, error) {
	store, group := value(in.IdentityStoreId), value(in.GroupId)
	user, e := memberID(in.MemberId)
	if e != nil {
		return nil, e
	}
	if e := s.admit(tx, "CreateGroupMembership", store, user, group, ""); e != nil {
		return nil, e
	}
	if _, e := tx.User(Key{store, user}); e != nil {
		return nil, e
	}
	if _, e := tx.Group(Key{store, group}); e != nil {
		return nil, e
	}
	if _, e := tx.MembershipFor(store, user, group); e == nil {
		return nil, conflict("The user is already a member of the group.")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	id, e := resourceID(store)
	if e != nil {
		return nil, e
	}
	if e := tx.PutMembership(Membership{StoreID: store, ID: id, UserID: user, GroupID: group}); e != nil {
		return nil, e
	}
	return &api.CreateGroupMembershipOutput{IdentityStoreId: in.IdentityStoreId, MembershipId: new(api.ResourceId(id))}, nil
}
func (s *Service) membership(tx Transaction, action, store, id string) (Membership, error) {
	if e := s.admit(tx, action, store, "", "", id); e != nil {
		return Membership{}, e
	}
	m, e := tx.Membership(Key{store, id})
	if e != nil {
		return Membership{}, e
	}
	if e := s.admit(tx, action, store, m.UserID, m.GroupID, id); e != nil {
		return Membership{}, e
	}
	return m, nil
}
func (s *Service) deleteMembership(tx Transaction, in *api.DeleteGroupMembershipInput) (*api.DeleteGroupMembershipOutput, error) {
	store, id := value(in.IdentityStoreId), value(in.MembershipId)
	if _, e := s.membership(tx, "DeleteGroupMembership", store, id); e != nil {
		return nil, e
	}
	return &api.DeleteGroupMembershipOutput{}, tx.DeleteMembership(Key{store, id})
}
func (s *Service) describeMembership(tx Transaction, in *api.DescribeGroupMembershipInput) (*api.DescribeGroupMembershipOutput, error) {
	m, e := s.membership(tx, "DescribeGroupMembership", value(in.IdentityStoreId), value(in.MembershipId))
	if e != nil {
		return nil, e
	}
	out := api.DescribeGroupMembershipOutput(apiMembership(m))
	return &out, nil
}
func (s *Service) getMembershipID(tx Transaction, in *api.GetGroupMembershipIdInput) (*api.GetGroupMembershipIdOutput, error) {
	store, group := value(in.IdentityStoreId), value(in.GroupId)
	user, e := memberID(in.MemberId)
	if e != nil {
		return nil, e
	}
	if e := s.admit(tx, "GetGroupMembershipId", store, user, group, ""); e != nil {
		return nil, e
	}
	m, e := tx.MembershipFor(store, user, group)
	if e != nil {
		return nil, e
	}
	if e := s.admit(tx, "GetGroupMembershipId", store, user, group, m.ID); e != nil {
		return nil, e
	}
	return &api.GetGroupMembershipIdOutput{IdentityStoreId: in.IdentityStoreId, MembershipId: new(api.ResourceId(m.ID))}, nil
}
func apiMembership(v Membership) api.GroupMembership {
	return api.GroupMembership{IdentityStoreId: new(api.IdentityStoreId(v.StoreID)), MembershipId: new(api.ResourceId(v.ID)), GroupId: new(api.ResourceId(v.GroupID)), MemberId: &api.MemberId{UserId: new(api.ResourceId(v.UserID))}}
}
func membershipPage(rows []Membership, query string, max *api.MaxResults, token *api.NextToken) (api.GroupMemberships, *api.NextToken, error) {
	rows, next, e := page(rows, query, max, token, func(v Membership) string { return v.ID })
	if e != nil {
		return nil, nil, e
	}
	out := api.GroupMemberships{}
	for _, v := range rows {
		out = append(out, apiMembership(v))
	}
	return out, next, nil
}
func (s *Service) listMemberships(tx Transaction, in *api.ListGroupMembershipsInput) (*api.ListGroupMembershipsOutput, error) {
	store, group := value(in.IdentityStoreId), value(in.GroupId)
	if e := s.admit(tx, "ListGroupMemberships", store, "", group, "*"); e != nil {
		return nil, e
	}
	if _, e := tx.Group(Key{store, group}); e != nil {
		return nil, e
	}
	rows, e := tx.Memberships(store, "", group)
	if e != nil {
		return nil, e
	}
	out, next, e := membershipPage(rows, queryKey("ListGroupMemberships", store, group), in.MaxResults, in.NextToken)
	if e != nil {
		return nil, e
	}
	return &api.ListGroupMembershipsOutput{GroupMemberships: out, NextToken: next}, nil
}
func (s *Service) listMembershipsForMember(tx Transaction, in *api.ListGroupMembershipsForMemberInput) (*api.ListGroupMembershipsForMemberOutput, error) {
	store := value(in.IdentityStoreId)
	user, e := memberID(in.MemberId)
	if e != nil {
		return nil, e
	}
	if e := s.admit(tx, "ListGroupMembershipsForMember", store, user, "", "*"); e != nil {
		return nil, e
	}
	if _, e := tx.User(Key{store, user}); e != nil {
		return nil, e
	}
	rows, e := tx.Memberships(store, user, "")
	if e != nil {
		return nil, e
	}
	out, next, e := membershipPage(rows, queryKey("ListGroupMembershipsForMember", store, user), in.MaxResults, in.NextToken)
	if e != nil {
		return nil, e
	}
	return &api.ListGroupMembershipsForMemberOutput{GroupMemberships: out, NextToken: next}, nil
}
func (s *Service) isMemberInGroups(tx Transaction, in *api.IsMemberInGroupsInput) (*api.IsMemberInGroupsOutput, error) {
	store := value(in.IdentityStoreId)
	user, e := memberID(in.MemberId)
	if e != nil {
		return nil, e
	}
	if e := s.admit(tx, "IsMemberInGroups", store, user, "", "*"); e != nil {
		return nil, e
	}
	out := &api.IsMemberInGroupsOutput{Results: api.GroupMembershipExistenceResults{}}
	for _, id := range in.GroupIds {
		if e := s.admit(tx, "IsMemberInGroups", store, user, string(id), "*"); e != nil {
			return nil, e
		}
		_, e := tx.MembershipFor(store, user, string(id))
		if e != nil && !errors.Is(e, ErrNotFound) {
			return nil, e
		}
		out.Results = append(out.Results, api.GroupMembershipExistenceResult{GroupId: new(id), MemberId: in.MemberId, MembershipExists: new(api.BooleanType(e == nil))})
	}
	return out, nil
}
