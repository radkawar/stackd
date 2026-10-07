package cognitoidp

import (
	api "stackd/internal/awsapi/cognitoidp"
	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite/cognitoidp/internal/sqlcgen"
	"time"
)

func (r reader) userRow(row sqlcgen.CognitoidpUser) (domain.UserRecord, error) {
	out := domain.UserRecord{
		Key: domain.UserKey{PoolKey: domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID}, Username: row.Username},
		Data: api.UserType{
			Username:             new(api.UsernameType(row.Username)),
			Enabled:              boolPointer[api.BooleanType](row.Enabled),
			UserCreateDate:       timePointer(row.UserCreateDate),
			UserLastModifiedDate: timePointer(row.UserLastModifiedDate),
			UserStatus:           stringPointer[api.UserStatusType](row.UserStatus),
		},
		Password:                   domain.PasswordVerifier{Salt: row.PasswordSalt, Verifier: row.PasswordVerifier},
		PasswordExpires:            timePointer(row.PasswordExpires),
		SoftwareTokenSecret:        row.SoftwareTokenSecret,
		SoftwareTokenPendingSecret: row.SoftwareTokenPendingSecret,
		SoftwareTokenLastCounter:   row.SoftwareTokenLastCounter,
		SoftwareTokenEnabled:       row.SoftwareTokenEnabled,
		SoftwareTokenPreferred:     row.SoftwareTokenPreferred,
		SoftwareTokenDeviceName:    row.SoftwareTokenDeviceName,
	}
	if row.SoftwareTokenPendingExpires.Valid {
		out.SoftwareTokenPendingExpires = row.SoftwareTokenPendingExpires.Time.UTC()
	}
	if err := unmarshalFields(jsonReadField{row.MfaOptions, &out.Data.MFAOptions}); err != nil {
		return domain.UserRecord{}, err
	}
	if row.AttributesPresent {
		attrs, err := r.q.ListUserAttributes(r.ctx, sqlcgen.ListUserAttributesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, PoolID: row.PoolID, Username: row.Username})
		if err != nil {
			return domain.UserRecord{}, err
		}
		out.Data.Attributes = make(api.AttributeListType, len(attrs))
		for i, attr := range attrs {
			out.Data.Attributes[i] = api.AttributeType{Name: stringPointer[api.AttributeNameType](attr.Name), Value: stringPointer[api.AttributeValueType](attr.Value)}
		}
	}
	return out, nil
}

func (r reader) User(k domain.UserKey) (domain.UserRecord, error) {
	row, err := r.q.GetUser(r.ctx, sqlcgen.GetUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username})
	if err != nil {
		return domain.UserRecord{}, missing(err)
	}
	return r.userRow(row)
}

func (r reader) Users(k domain.PoolKey) ([]domain.UserRecord, error) {
	rows, err := r.q.ListUsers(r.ctx, sqlcgen.ListUsersParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID})
	if err != nil {
		return nil, err
	}
	return r.userRows(rows)
}

func (r reader) UsersByAttribute(k domain.PoolKey, name, value string) ([]domain.UserRecord, error) {
	rows, err := r.q.ListUsersByAttribute(r.ctx, sqlcgen.ListUsersByAttributeParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID,
		Name: nullableString(&name), Value: nullableString(&value),
	})
	if err != nil {
		return nil, err
	}
	return r.userRows(rows)
}

func (r reader) userRows(rows []sqlcgen.CognitoidpUser) ([]domain.UserRecord, error) {
	out := make([]domain.UserRecord, len(rows))
	for i, row := range rows {
		var err error
		out[i], err = r.userRow(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (w writer) PutUser(v domain.UserRecord) error {
	k := v.Key
	row := sqlcgen.PutUserParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username,
		Enabled: nullableBool(v.Data.Enabled), UserCreateDate: nullableTime(v.Data.UserCreateDate),
		UserLastModifiedDate: nullableTime(v.Data.UserLastModifiedDate), UserStatus: nullableString(v.Data.UserStatus),
		AttributesPresent: v.Data.Attributes != nil, PasswordSalt: v.Password.Salt, PasswordVerifier: v.Password.Verifier,
		PasswordExpires:             nullableTime(v.PasswordExpires),
		SoftwareTokenSecret:         v.SoftwareTokenSecret,
		SoftwareTokenPendingSecret:  v.SoftwareTokenPendingSecret,
		SoftwareTokenPendingExpires: nullableTime(ptrTimeNonzero(v.SoftwareTokenPendingExpires)),
		SoftwareTokenLastCounter:    v.SoftwareTokenLastCounter,
		SoftwareTokenEnabled:        v.SoftwareTokenEnabled,
		SoftwareTokenPreferred:      v.SoftwareTokenPreferred,
		SoftwareTokenDeviceName:     v.SoftwareTokenDeviceName,
	}
	if err := marshalFields(jsonWriteField{&row.MfaOptions, v.Data.MFAOptions}); err != nil {
		return err
	}
	if err := w.q.PutUser(w.ctx, row); err != nil {
		return err
	}
	if err := w.q.DeleteUserAttributes(w.ctx, sqlcgen.DeleteUserAttributesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username}); err != nil {
		return err
	}
	for i, attr := range v.Data.Attributes {
		if err := w.q.PutUserAttribute(w.ctx, sqlcgen.PutUserAttributeParams{
			Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username,
			Position: int64(i), Name: nullableString(attr.Name), Value: nullableString(attr.Value),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteUser(k domain.UserKey) error {
	if err := w.q.DeleteOAuthForUser(w.ctx, sqlcgen.DeleteOAuthForUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username}); err != nil {
		return err
	}
	if err := w.RevokeUserSessions(k); err != nil {
		return err
	}
	if err := w.q.DeleteUser(w.ctx, sqlcgen.DeleteUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username}); err != nil {
		return err
	}
	if err := w.q.DeleteMembershipOwnersByUser(w.ctx, sqlcgen.DeleteMembershipOwnersByUserParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, MemberUser: k.Username}); err != nil {
		return err
	}
	return w.releaseOwners(k.PoolKey, k.Username, domain.OwnerKindUser)
}

func (w writer) RevokeUserSessions(k domain.UserKey) error {
	return w.q.RevokeUserSessions(w.ctx, sqlcgen.RevokeUserSessionsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID, Username: k.Username})
}

func ptrTimeNonzero(v time.Time) *time.Time {
	if v.IsZero() {
		return nil
	}
	return &v
}
