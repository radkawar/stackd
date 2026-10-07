package lambda

import (
	"database/sql"
	"encoding/json"
	"errors"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) FunctionURL(k domain.FunctionReference) (domain.FunctionURLRecord, error) {
	v, err := r.q.GetFunctionURL(r.ctx, sqlcgen.GetFunctionURLParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.FunctionURLRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.FunctionURLRecord{}, err
	}
	return functionURLRecord(v)
}

func (r reader) FunctionURLByID(id string) (domain.FunctionURLRecord, error) {
	v, err := r.q.GetFunctionURLByID(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.FunctionURLRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.FunctionURLRecord{}, err
	}
	return functionURLRecord(v)
}

func (r reader) FunctionURLs(k domain.FunctionKey) ([]domain.FunctionURLRecord, error) {
	rows, err := r.q.ListFunctionURLs(r.ctx, sqlcgen.ListFunctionURLsParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.FunctionURLRecord, 0, len(rows))
	for _, row := range rows {
		v, err := functionURLRecord(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func functionURLRecord(v sqlcgen.LambdaFunctionUrl) (domain.FunctionURLRecord, error) {
	out := domain.FunctionURLRecord{
		Key:   domain.FunctionReference{FunctionKey: domain.FunctionKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.FunctionName}, Qualifier: v.Qualifier},
		Owner: domain.AdditionalOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken},
		ID:    v.ID, Created: v.Created, Modified: v.Modified, AppliesAt: v.AppliesAt,
		Settings:  domain.FunctionURLSettings{AuthType: v.AuthType, InvokeMode: v.InvokeMode},
		Effective: domain.FunctionURLSettings{AuthType: v.EffectiveAuthType, InvokeMode: v.EffectiveInvokeMode},
	}
	var err error
	out.Settings.Cors, err = readFunctionURLCORS(v.CorsPresent, v.AllowCredentials, v.AllowHeaders, v.AllowMethods, v.AllowOrigins, v.ExposeHeaders, v.MaxAge)
	if err != nil {
		return domain.FunctionURLRecord{}, err
	}
	out.Effective.Cors, err = readFunctionURLCORS(v.EffectiveCorsPresent, v.EffectiveAllowCredentials, v.EffectiveAllowHeaders, v.EffectiveAllowMethods, v.EffectiveAllowOrigins, v.EffectiveExposeHeaders, v.EffectiveMaxAge)
	if err != nil {
		return domain.FunctionURLRecord{}, err
	}
	return out, nil
}

func readFunctionURLCORS(present bool, credentials sql.NullBool, headers, methods, origins, exposed sql.NullString, age sql.NullInt64) (*domain.FunctionURLCORS, error) {
	if !present {
		return nil, nil
	}
	out := &domain.FunctionURLCORS{}
	if credentials.Valid {
		out.AllowCredentials = new(credentials.Bool)
	}
	if age.Valid {
		out.MaxAge = new(int32(age.Int64))
	}
	for _, field := range []struct {
		source sql.NullString
		target *[]string
	}{
		{headers, &out.AllowHeaders}, {methods, &out.AllowMethods}, {origins, &out.AllowOrigins}, {exposed, &out.ExposeHeaders},
	} {
		if field.source.Valid {
			if err := json.Unmarshal([]byte(field.source.String), field.target); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func functionURLStringList(v []string) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	// A typed string list has no unsupported JSON values.
	data, _ := json.Marshal(v)
	return sql.NullString{String: string(data), Valid: true}
}

func (w writer) PutFunctionURL(v domain.FunctionURLRecord) error {
	k := v.Key
	params := sqlcgen.PutFunctionURLParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier,
		OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token,
		ID: v.ID, Created: v.Created, Modified: v.Modified, AppliesAt: v.AppliesAt,
		AuthType: v.Settings.AuthType, InvokeMode: v.Settings.InvokeMode,
		EffectiveAuthType: v.Effective.AuthType, EffectiveInvokeMode: v.Effective.InvokeMode,
	}
	if cors := v.Settings.Cors; cors != nil {
		params.CorsPresent = true
		if cors.AllowCredentials != nil {
			params.AllowCredentials = sql.NullBool{Bool: *cors.AllowCredentials, Valid: true}
		}
		if cors.MaxAge != nil {
			params.MaxAge = sql.NullInt64{Int64: int64(*cors.MaxAge), Valid: true}
		}
		params.AllowHeaders = functionURLStringList(cors.AllowHeaders)
		params.AllowMethods = functionURLStringList(cors.AllowMethods)
		params.AllowOrigins = functionURLStringList(cors.AllowOrigins)
		params.ExposeHeaders = functionURLStringList(cors.ExposeHeaders)
	}
	if cors := v.Effective.Cors; cors != nil {
		params.EffectiveCorsPresent = true
		if cors.AllowCredentials != nil {
			params.EffectiveAllowCredentials = sql.NullBool{Bool: *cors.AllowCredentials, Valid: true}
		}
		if cors.MaxAge != nil {
			params.EffectiveMaxAge = sql.NullInt64{Int64: int64(*cors.MaxAge), Valid: true}
		}
		params.EffectiveAllowHeaders = functionURLStringList(cors.AllowHeaders)
		params.EffectiveAllowMethods = functionURLStringList(cors.AllowMethods)
		params.EffectiveAllowOrigins = functionURLStringList(cors.AllowOrigins)
		params.EffectiveExposeHeaders = functionURLStringList(cors.ExposeHeaders)
	}
	return w.q.PutFunctionURL(w.ctx, params)
}

func (w writer) DeleteFunctionURL(k domain.FunctionReference) error {
	return w.q.DeleteFunctionURL(w.ctx, sqlcgen.DeleteFunctionURLParams{Partition: k.Partition, Account: k.Account, Region: k.Region, FunctionName: k.Name, Qualifier: k.Qualifier})
}
