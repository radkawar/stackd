package appsync

import (
	"context"
	"errors"
)

type cfnOwnershipKey struct{}
type cfnSchemaOperationKey struct{}
type cfnDesiredAPIKey struct{}

// Full CFN models remove omitted configurations; ordinary API patches retain them.
func WithCloudFormationDesiredAPI(ctx context.Context) context.Context {
	return context.WithValue(ctx, cfnDesiredAPIKey{}, true)
}

// Schema operations remain authorized by StartSchemaCreation/GetIntrospectionSchema.
func WithCloudFormationSchemaDeletion(ctx context.Context) context.Context {
	return context.WithValue(ctx, cfnSchemaOperationKey{}, "delete")
}
func WithCloudFormationSchemaRead(ctx context.Context) context.Context {
	return context.WithValue(ctx, cfnSchemaOperationKey{}, "read")
}

type cfnOwnership struct {
	Kind, Claim, Target string
	Enforce             bool
	Rows                map[string]string
}

// WithCloudFormationOwnership scopes claims to existing service rows, not a
// parallel resource database. Get/list operations collect recovery identities.
func WithCloudFormationOwnership(ctx context.Context, kind, claim, target string, enforce bool, rows map[string]string) context.Context {
	return context.WithValue(ctx, cfnOwnershipKey{}, &cfnOwnership{kind, claim, target, enforce, rows})
}

type cfnOwnershipTransaction struct {
	Transaction
	b *cfnOwnership
}

func bindCloudFormationOwnership(tx Transaction) Transaction {
	b, _ := tx.Context().Value(cfnOwnershipKey{}).(*cfnOwnership)
	return &cfnOwnershipTransaction{tx, b}
}
func (t *cfnOwnershipTransaction) observe(kind, id, claim string) error {
	b := t.b
	if b == nil || b.Kind != kind {
		return nil
	}
	if b.Rows != nil {
		b.Rows[id] = claim
	}
	if b.Enforce && (b.Target == "" || b.Target == id) && claim != b.Claim {
		return failure("ConflictException", "Resource belongs to another CloudFormation incarnation", 409)
	}
	return nil
}
func (t *cfnOwnershipTransaction) stamp(kind, id string, claim *string) {
	if b := t.b; b != nil && b.Kind == kind && (b.Target == "" || b.Target == id) {
		*claim = b.Claim
	}
}
func (t *cfnOwnershipTransaction) API(k Key) (APIRecord, error) {
	v, e := t.Transaction.API(k)
	if e == nil && !(t.Context().Value(cfnSchemaOperationKey{}) == "delete" && v.SchemaOwnership == "" && v.Schema == "") {
		e = t.observe("GraphQLSchema", k.ID, v.SchemaOwnership)
	}
	if e == nil {
		e = t.observe("GraphQLApi", k.ID, v.Ownership)
	}
	return v, e
}
func (t *cfnOwnershipTransaction) APIs() ([]APIRecord, error) {
	rows, e := t.Transaction.APIs()
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("GraphQLSchema", v.Key.ID, v.SchemaOwnership); e != nil {
			return nil, e
		}
		if e = t.observe("GraphQLApi", v.Key.ID, v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cfnOwnershipTransaction) PutAPI(v APIRecord) error {
	old, e := t.Transaction.API(v.Key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if errors.Is(e, ErrNotFound) && t.b != nil && t.b.Kind == "GraphQLApi" && !t.b.Enforce {
		rows, err := t.Transaction.APIs()
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Key.Partition == v.Key.Partition && row.Key.AccountID == v.Key.AccountID && row.Key.Region == v.Key.Region && row.Ownership == t.b.Claim {
				return failure("ConflictException", "API incarnation already admitted", 409)
			}
		}
	}
	if e == nil {
		if e = t.observe("GraphQLApi", v.Key.ID, old.Ownership); e != nil {
			return e
		}
		v.Ownership = old.Ownership
		if b := t.b; b != nil && b.Kind == "GraphQLApi" && (b.Target == "" || b.Target == v.Key.ID) && !b.Enforce && old.Ownership != b.Claim {
			return failure("ConflictException", "API already exists outside this incarnation", 409)
		}
	} else if b := t.b; b != nil && b.Kind == "GraphQLApi" && b.Enforce {
		return failure("ConflictException", "API incarnation no longer exists", 409)
	}
	t.stamp("GraphQLApi", v.Key.ID, &v.Ownership)
	t.stamp("GraphQLSchema", v.Key.ID, &v.SchemaOwnership)
	if t.Context().Value(cfnSchemaOperationKey{}) == "delete" {
		v.SchemaOwnership = ""
	}
	return t.Transaction.PutAPI(v)
}
func (t *cfnOwnershipTransaction) DeleteAPI(k Key) error {
	if _, e := t.API(k); e != nil {
		return e
	}
	return t.Transaction.DeleteAPI(k)
}
func (t *cfnOwnershipTransaction) DataSources(k Key) ([]DataSourceRecord, error) {
	rows, e := t.Transaction.DataSources(k)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("DataSource", k.ID+"/"+value(v.DataSource.Name), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cfnOwnershipTransaction) PutDataSource(v DataSourceRecord) error {
	rows, e := t.Transaction.DataSources(v.API)
	if e != nil {
		return e
	}
	id := v.API.ID + "/" + value(v.DataSource.Name)
	for _, old := range rows {
		if value(old.DataSource.Name) == value(v.DataSource.Name) {
			if e = t.observe("DataSource", id, old.Ownership); e != nil {
				return e
			}
			v.Ownership = old.Ownership
		}
	}
	t.stamp("DataSource", id, &v.Ownership)
	return t.Transaction.PutDataSource(v)
}
func (t *cfnOwnershipTransaction) DeleteDataSource(k Key, name string) error {
	rows, e := t.DataSources(k)
	if e != nil {
		return e
	}
	for _, v := range rows {
		if value(v.DataSource.Name) == name {
			if e = t.observe("DataSource", k.ID+"/"+name, v.Ownership); e != nil {
				return e
			}
		}
	}
	return t.Transaction.DeleteDataSource(k, name)
}
func (t *cfnOwnershipTransaction) Functions(k Key) ([]FunctionRecord, error) {
	rows, e := t.Transaction.Functions(k)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("FunctionConfiguration", k.ID+"/"+value(v.Function.FunctionId), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cfnOwnershipTransaction) PutFunction(v FunctionRecord) error {
	rows, e := t.Transaction.Functions(v.API)
	if e != nil {
		return e
	}
	id := v.API.ID + "/" + value(v.Function.FunctionId)
	for _, old := range rows {
		if value(old.Function.FunctionId) == value(v.Function.FunctionId) {
			if e = t.observe("FunctionConfiguration", id, old.Ownership); e != nil {
				return e
			}
			v.Ownership = old.Ownership
		}
	}
	t.stamp("FunctionConfiguration", id, &v.Ownership)
	return t.Transaction.PutFunction(v)
}
func (t *cfnOwnershipTransaction) DeleteFunction(k Key, id string) error {
	if _, e := t.Functions(k); e != nil {
		return e
	}
	return t.Transaction.DeleteFunction(k, id)
}
func (t *cfnOwnershipTransaction) Resolvers(k Key) ([]ResolverRecord, error) {
	rows, e := t.Transaction.Resolvers(k)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("Resolver", k.ID+"/"+value(v.Resolver.TypeName)+"/"+value(v.Resolver.FieldName), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cfnOwnershipTransaction) PutResolver(v ResolverRecord) error {
	rows, e := t.Transaction.Resolvers(v.API)
	if e != nil {
		return e
	}
	id := v.API.ID + "/" + value(v.Resolver.TypeName) + "/" + value(v.Resolver.FieldName)
	for _, old := range rows {
		if resolverID(old.Resolver) == resolverID(v.Resolver) {
			if e = t.observe("Resolver", id, old.Ownership); e != nil {
				return e
			}
			v.Ownership = old.Ownership
		}
	}
	t.stamp("Resolver", id, &v.Ownership)
	return t.Transaction.PutResolver(v)
}
func (t *cfnOwnershipTransaction) DeleteResolver(k Key, typ, field string) error {
	if _, e := t.Resolvers(k); e != nil {
		return e
	}
	return t.Transaction.DeleteResolver(k, typ, field)
}
func (t *cfnOwnershipTransaction) APIKeys(k Key) ([]APIKeyRecord, error) {
	rows, e := t.Transaction.APIKeys(k)
	if e != nil {
		return nil, e
	}
	for _, v := range rows {
		if e = t.observe("ApiKey", k.ID+"/"+value(v.Key.Id), v.Ownership); e != nil {
			return nil, e
		}
	}
	return rows, nil
}
func (t *cfnOwnershipTransaction) PutAPIKey(v APIKeyRecord) error {
	rows, e := t.Transaction.APIKeys(v.API)
	if e != nil {
		return e
	}
	id := v.API.ID + "/" + value(v.Key.Id)
	for _, old := range rows {
		if value(old.Key.Id) == value(v.Key.Id) {
			if e = t.observe("ApiKey", id, old.Ownership); e != nil {
				return e
			}
			v.Ownership = old.Ownership
		}
	}
	t.stamp("ApiKey", id, &v.Ownership)
	return t.Transaction.PutAPIKey(v)
}
func (t *cfnOwnershipTransaction) DeleteAPIKey(k Key, id string) error {
	if _, e := t.APIKeys(k); e != nil {
		return e
	}
	return t.Transaction.DeleteAPIKey(k, id)
}
