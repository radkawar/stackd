package cognitoidp

import (
	"cmp"
	"maps"
	"slices"

	api "stackd/internal/awsapi/cognitoidp"
)

func copyGroupRecord(v GroupRecord) GroupRecord {
	v.Data = api.CloneGroupType(v.Data)
	return v
}

func (r memoryReader) Group(k GroupKey) (GroupRecord, error) {
	return memoryRow(r.tx, r.s.groups, k, copyGroupRecord)
}

func (r memoryReader) Groups(pool PoolKey) ([]GroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	rows := make([]GroupRecord, 0)
	for key, row := range r.s.groups {
		if key.PoolKey == pool {
			rows = append(rows, copyGroupRecord(row))
		}
	}
	slices.SortFunc(rows, func(a, b GroupRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (r memoryReader) GroupsForUser(k UserKey) ([]GroupRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	names := r.s.userGroups[k]
	rows := make([]GroupRecord, 0, len(names))
	for name := range names {
		rows = append(rows, copyGroupRecord(r.s.groups[GroupKey{PoolKey: k.PoolKey, Name: name}]))
	}
	slices.SortFunc(rows, func(a, b GroupRecord) int { return cmp.Compare(a.Key.Name, b.Key.Name) })
	return rows, nil
}

func (r memoryReader) UsersInGroup(k GroupKey) ([]UserRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	names := r.s.groupUsers[k]
	rows := make([]UserRecord, 0, len(names))
	for name := range names {
		rows = append(rows, copyUserRecord(r.s.users[UserKey{PoolKey: k.PoolKey, Username: name}]))
	}
	slices.SortFunc(rows, func(a, b UserRecord) int { return cmp.Compare(a.Key.Username, b.Key.Username) })
	return rows, nil
}

func (w memoryWriter) PutGroup(v GroupRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.groups[v.Key] = copyGroupRecord(v)
	return nil
}

func (w memoryWriter) AddGroupUser(k GroupKey, username string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	user := UserKey{PoolKey: k.PoolKey, Username: username}
	if _, ok := w.s.groupUsers[k][username]; ok {
		return nil
	}
	// Membership buckets, like attribute-index buckets, remain immutable
	// between writes so shared-domain attempts can roll back both directions.
	members := maps.Clone(w.s.groupUsers[k])
	if members == nil {
		members = make(map[string]struct{})
	}
	members[username] = struct{}{}
	w.s.groupUsers[k] = members
	groups := maps.Clone(w.s.userGroups[user])
	if groups == nil {
		groups = make(map[string]struct{})
	}
	groups[k.Name] = struct{}{}
	w.s.userGroups[user] = groups
	return nil
}

func (w memoryWriter) RemoveGroupUser(k GroupKey, username string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.groupUsers[k][username]; !ok {
		return nil
	}
	removeMembership(w.s.groupUsers, k, username)
	removeMembership(w.s.userGroups, UserKey{PoolKey: k.PoolKey, Username: username}, k.Name)
	w.releaseOwners(k.PoolKey, func(v OwnershipRecord) bool {
		return v.Key.Kind == OwnerKindMembership && v.MemberUser == username && v.MemberGroup == k.Name
	})
	return nil
}

func removeMembership[K comparable](index map[K]map[string]struct{}, key K, name string) {
	members := index[key]
	if len(members) == 1 {
		delete(index, key)
		return
	}
	members = maps.Clone(members)
	delete(members, name)
	index[key] = members
}

func (w memoryWriter) DeleteGroup(k GroupKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	for username := range w.s.groupUsers[k] {
		removeMembership(w.s.userGroups, UserKey{PoolKey: k.PoolKey, Username: username}, k.Name)
	}
	delete(w.s.groupUsers, k)
	delete(w.s.groups, k)
	w.releaseOwners(k.PoolKey, func(v OwnershipRecord) bool {
		return v.Key.Kind == OwnerKindGroup && v.PhysicalID == k.Name || v.Key.Kind == OwnerKindMembership && v.MemberGroup == k.Name
	})
	return nil
}

func (w memoryWriter) removeUserGroups(k UserKey) {
	for name := range w.s.userGroups[k] {
		removeMembership(w.s.groupUsers, GroupKey{PoolKey: k.PoolKey, Name: name}, k.Username)
	}
	delete(w.s.userGroups, k)
}
