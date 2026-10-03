package cognitoidp

import (
	api "stackd/internal/awsapi/cognitoidp"
	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite/cognitoidp/internal/sqlcgen"
)

func groupRow(row sqlcgen.CognitoidpGroup) domain.GroupRecord {
	return domain.GroupRecord{
		Key: domain.GroupKey{PoolKey: domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID}, Name: row.GroupName},
		Data: api.GroupType{
			GroupName:        new(api.GroupNameType(row.GroupName)),
			UserPoolId:       new(api.UserPoolIdType(row.PoolID)),
			CreationDate:     timePointer(row.CreationDate),
			Description:      stringPointer[api.DescriptionType](row.Description),
			LastModifiedDate: timePointer(row.LastModifiedDate),
			Precedence:       integerPointer[api.PrecedenceType](row.Precedence),
			RoleArn:          stringPointer[api.ArnType](row.RoleArn),
		},
	}
}

func groupRows(rows []sqlcgen.CognitoidpGroup) []domain.GroupRecord {
	out := make([]domain.GroupRecord, len(rows))
	for i, row := range rows {
		out[i] = groupRow(row)
	}
	return out
}

func (r reader) Group(k domain.GroupKey) (domain.GroupRecord, error) {
	row, err := r.q.GetGroup(r.ctx, sqlcgen.GetGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, GroupName: k.Name})
	if err != nil {
		return domain.GroupRecord{}, missing(err)
	}
	return groupRow(row), nil
}

func (r reader) Groups(k domain.PoolKey) ([]domain.GroupRecord, error) {
	rows, err := r.q.ListGroups(r.ctx, sqlcgen.ListGroupsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID})
	if err != nil {
		return nil, err
	}
	return groupRows(rows), nil
}

func (r reader) GroupsForUser(k domain.UserKey) ([]domain.GroupRecord, error) {
	rows, err := r.q.ListGroupsForUser(r.ctx, sqlcgen.ListGroupsForUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username})
	if err != nil {
		return nil, err
	}
	return groupRows(rows), nil
}

func (r reader) UsersInGroup(k domain.GroupKey) ([]domain.UserRecord, error) {
	rows, err := r.q.ListUsersInGroup(r.ctx, sqlcgen.ListUsersInGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, GroupName: k.Name})
	if err != nil {
		return nil, err
	}
	return r.userRows(rows)
}

func (w writer) PutGroup(v domain.GroupRecord) error {
	k := v.Key
	return w.q.PutGroup(w.ctx, sqlcgen.PutGroupParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, GroupName: k.Name,
		CreationDate: nullableTime(v.Data.CreationDate), Description: nullableString(v.Data.Description),
		LastModifiedDate: nullableTime(v.Data.LastModifiedDate), Precedence: nullableInteger(v.Data.Precedence),
		RoleArn: nullableString(v.Data.RoleArn),
	})
}

func (w writer) DeleteGroup(k domain.GroupKey) error {
	return w.q.DeleteGroup(w.ctx, sqlcgen.DeleteGroupParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, GroupName: k.Name})
}

func (w writer) AddGroupUser(k domain.GroupKey, username string) error {
	return w.q.AddGroupUser(w.ctx, sqlcgen.AddGroupUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, GroupName: k.Name, Username: username})
}

func (w writer) RemoveGroupUser(k domain.GroupKey, username string) error {
	return w.q.RemoveGroupUser(w.ctx, sqlcgen.RemoveGroupUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, GroupName: k.Name, Username: username})
}
