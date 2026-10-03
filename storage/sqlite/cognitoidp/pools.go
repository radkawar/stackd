package cognitoidp

import (
	api "stackd/internal/awsapi/cognitoidp"
	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite/cognitoidp/internal/sqlcgen"
)

func poolRow(row sqlcgen.CognitoidpPool) (domain.PoolRecord, error) {
	out := domain.PoolRecord{
		Key:       domain.PoolKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.PoolID},
		IssuerURL: row.IssuerUrl,
		Data: api.UserPoolType{
			Id:                        new(api.UserPoolIdType(row.PoolID)),
			Arn:                       stringPointer[api.ArnType](row.Arn),
			CreationDate:              timePointer(row.CreationDate),
			CustomDomain:              stringPointer[api.DomainType](row.CustomDomain),
			DeletionProtection:        stringPointer[api.DeletionProtectionType](row.DeletionProtection),
			Domain:                    stringPointer[api.DomainType](row.Domain),
			EmailConfigurationFailure: stringPointer[api.StringType](row.EmailConfigurationFailure),
			EmailVerificationMessage:  stringPointer[api.EmailVerificationMessageType](row.EmailVerificationMessage),
			EmailVerificationSubject:  stringPointer[api.EmailVerificationSubjectType](row.EmailVerificationSubject),
			EstimatedNumberOfUsers:    integerPointer[api.IntegerType](row.EstimatedNumberOfUsers),
			LastModifiedDate:          timePointer(row.LastModifiedDate),
			MfaConfiguration:          stringPointer[api.UserPoolMfaType](row.MfaConfiguration),
			Name:                      stringPointer[api.UserPoolNameType](row.Name),
			SmsAuthenticationMessage:  stringPointer[api.SmsVerificationMessageType](row.SmsAuthenticationMessage),
			SmsConfigurationFailure:   stringPointer[api.StringType](row.SmsConfigurationFailure),
			SmsVerificationMessage:    stringPointer[api.SmsVerificationMessageType](row.SmsVerificationMessage),
			Status:                    stringPointer[api.StatusType](row.Status),
			UserPoolTier:              stringPointer[api.UserPoolTierType](row.UserPoolTier),
		},
	}
	err := unmarshalFields(
		jsonReadField{row.AccountRecoverySetting, &out.Data.AccountRecoverySetting},
		jsonReadField{row.AdminCreateUserConfig, &out.Data.AdminCreateUserConfig},
		jsonReadField{row.AliasAttributes, &out.Data.AliasAttributes},
		jsonReadField{row.AutoVerifiedAttributes, &out.Data.AutoVerifiedAttributes},
		jsonReadField{row.DeviceConfiguration, &out.Data.DeviceConfiguration},
		jsonReadField{row.EmailConfiguration, &out.Data.EmailConfiguration},
		jsonReadField{row.IssuerConfiguration, &out.Data.IssuerConfiguration},
		jsonReadField{row.KeyConfiguration, &out.Data.KeyConfiguration},
		jsonReadField{row.LambdaConfig, &out.Data.LambdaConfig},
		jsonReadField{row.Policies, &out.Data.Policies},
		jsonReadField{row.SchemaAttributes, &out.Data.SchemaAttributes},
		jsonReadField{row.SmsConfiguration, &out.Data.SmsConfiguration},
		jsonReadField{row.UserAttributeUpdateSettings, &out.Data.UserAttributeUpdateSettings},
		jsonReadField{row.UserPoolAddOns, &out.Data.UserPoolAddOns},
		jsonReadField{row.UserPoolTags, &out.Data.UserPoolTags},
		jsonReadField{row.UsernameAttributes, &out.Data.UsernameAttributes},
		jsonReadField{row.UsernameConfiguration, &out.Data.UsernameConfiguration},
		jsonReadField{row.VerificationMessageTemplate, &out.Data.VerificationMessageTemplate},
	)
	return out, err
}

func (r reader) Pool(k domain.PoolKey) (domain.PoolRecord, error) {
	row, err := r.q.GetPool(r.ctx, sqlcgen.GetPoolParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID})
	if err != nil {
		return domain.PoolRecord{}, missing(err)
	}
	return poolRow(row)
}

func (r reader) PoolByID(partition, region, id string) (domain.PoolRecord, error) {
	row, err := r.q.GetPoolByID(r.ctx, sqlcgen.GetPoolByIDParams{Partition: partition, Region: region, PoolID: id})
	if err != nil {
		return domain.PoolRecord{}, missing(err)
	}
	return poolRow(row)
}

func (r reader) Pools(k domain.Scope) ([]domain.PoolRecord, error) {
	rows, err := r.q.ListPools(r.ctx, sqlcgen.ListPoolsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PoolRecord, len(rows))
	for i, row := range rows {
		out[i], err = poolRow(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r reader) PoolsForAccount(partition, accountID string) ([]domain.PoolRecord, error) {
	rows, err := r.q.ListPoolsForAccount(r.ctx, sqlcgen.ListPoolsForAccountParams{Partition: partition, AccountID: accountID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.PoolRecord, len(rows))
	for i, row := range rows {
		out[i], err = poolRow(row)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (w writer) PutPool(v domain.PoolRecord) error {
	k := v.Key
	row := sqlcgen.PutPoolParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID,
		IssuerUrl:                 v.IssuerURL,
		Arn:                       nullableString(v.Data.Arn),
		CreationDate:              nullableTime(v.Data.CreationDate),
		CustomDomain:              nullableString(v.Data.CustomDomain),
		DeletionProtection:        nullableString(v.Data.DeletionProtection),
		Domain:                    nullableString(v.Data.Domain),
		EmailConfigurationFailure: nullableString(v.Data.EmailConfigurationFailure),
		EmailVerificationMessage:  nullableString(v.Data.EmailVerificationMessage),
		EmailVerificationSubject:  nullableString(v.Data.EmailVerificationSubject),
		EstimatedNumberOfUsers:    nullableInteger(v.Data.EstimatedNumberOfUsers),
		LastModifiedDate:          nullableTime(v.Data.LastModifiedDate),
		MfaConfiguration:          nullableString(v.Data.MfaConfiguration),
		Name:                      nullableString(v.Data.Name),
		SmsAuthenticationMessage:  nullableString(v.Data.SmsAuthenticationMessage),
		SmsConfigurationFailure:   nullableString(v.Data.SmsConfigurationFailure),
		SmsVerificationMessage:    nullableString(v.Data.SmsVerificationMessage),
		Status:                    nullableString(v.Data.Status),
		UserPoolTier:              nullableString(v.Data.UserPoolTier),
	}
	if err := marshalFields(
		jsonWriteField{&row.AccountRecoverySetting, v.Data.AccountRecoverySetting},
		jsonWriteField{&row.AdminCreateUserConfig, v.Data.AdminCreateUserConfig},
		jsonWriteField{&row.AliasAttributes, v.Data.AliasAttributes},
		jsonWriteField{&row.AutoVerifiedAttributes, v.Data.AutoVerifiedAttributes},
		jsonWriteField{&row.DeviceConfiguration, v.Data.DeviceConfiguration},
		jsonWriteField{&row.EmailConfiguration, v.Data.EmailConfiguration},
		jsonWriteField{&row.IssuerConfiguration, v.Data.IssuerConfiguration},
		jsonWriteField{&row.KeyConfiguration, v.Data.KeyConfiguration},
		jsonWriteField{&row.LambdaConfig, v.Data.LambdaConfig},
		jsonWriteField{&row.Policies, v.Data.Policies},
		jsonWriteField{&row.SchemaAttributes, v.Data.SchemaAttributes},
		jsonWriteField{&row.SmsConfiguration, v.Data.SmsConfiguration},
		jsonWriteField{&row.UserAttributeUpdateSettings, v.Data.UserAttributeUpdateSettings},
		jsonWriteField{&row.UserPoolAddOns, v.Data.UserPoolAddOns},
		jsonWriteField{&row.UserPoolTags, v.Data.UserPoolTags},
		jsonWriteField{&row.UsernameAttributes, v.Data.UsernameAttributes},
		jsonWriteField{&row.UsernameConfiguration, v.Data.UsernameConfiguration},
		jsonWriteField{&row.VerificationMessageTemplate, v.Data.VerificationMessageTemplate},
	); err != nil {
		return err
	}
	return w.q.PutPool(w.ctx, row)
}

func (w writer) DeletePool(k domain.PoolKey) error {
	return w.q.DeletePool(w.ctx, sqlcgen.DeletePoolParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, PoolID: k.ID})
}
