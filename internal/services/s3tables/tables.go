package s3tables

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awswire"

	"github.com/google/uuid"
)

func (s *Service) table(ctx context.Context, r Reader, action, b, n, name string) (Table, error) {
	sc := scopeFor(ctx)
	prefix := bucketARN(sc, "")
	if !strings.HasPrefix(b, prefix) {
		return Table{}, ErrNotFound
	}
	if _, e := r.Bucket(sc, b); e != nil {
		return Table{}, e
	}
	v, e := r.Table(sc, b, n, name)
	if e != nil {
		return Table{}, e
	}
	if e = s.authorize(ctx, action, v.ARN, tableAuthorizationContext(v)); e != nil {
		return Table{}, e
	}
	return v, nil
}
func (s *Service) admitCreate(ctx context.Context, r Reader, in *api.CreateTableInput, candidate Table) error {
	sc := scopeFor(ctx)
	b := value(in.TableBucketARN)
	if !strings.HasPrefix(b, bucketARN(sc, "")) {
		return ErrNotFound
	}
	if _, e := r.Bucket(sc, b); e != nil {
		return e
	}
	if _, e := r.Namespace(sc, b, value(in.Namespace)); e != nil {
		return e
	}
	if !namePattern.MatchString(value(in.Name)) || value(in.Format) != "ICEBERG" {
		return invalid("A valid table name and ICEBERG format are required")
	}
	// TODO: Comeback support explicit encryption/storage settings and tag lifecycle
	// with their required authorization; default data encryption is not this API.
	if in.EncryptionConfiguration != nil || in.StorageClassConfiguration != nil || len(in.Tags) > 0 {
		return invalid("Explicit encryption, storage class and tags are not supported")
	}
	if e := s.authorize(ctx, "CreateTable", b, namespaceAuthorizationContext(candidate.Namespace)); e != nil {
		return e
	}
	if in.Metadata != nil {
		if e := s.authorize(ctx, "PutTableData", candidate.ARN, tableAuthorizationContext(candidate)); e != nil {
			return e
		}
	}
	if _, e := r.Table(sc, b, value(in.Namespace), value(in.Name)); e == nil {
		return conflict("Table already exists")
	} else if !errors.Is(e, ErrNotFound) {
		return e
	}
	return nil
}
func (s *Service) newTable(ctx context.Context, in *api.CreateTableInput) Table {
	id := uuid.NewString()
	now := s.clock.Now().UTC()
	return Table{Scope: scopeFor(ctx), BucketARN: value(in.TableBucketARN), Namespace: value(in.Namespace), Name: value(in.Name), ARN: value(in.TableBucketARN) + "/table/" + id, ID: id, VersionToken: uuid.NewString(), Warehouse: "s3://" + id + warehouseBucketSuffix, Created: now, Modified: now}
}

func (s *Service) rejectCreate(ctx context.Context, in *api.CreateTableInput, err error) (*api.CreateTableOutput, *awswire.Error) {
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if e := s.recordCall(completion, "CreateTable", in, nil, rejected); e != nil {
		return nil, wireError(e)
	}
	return nil, rejected
}
func (s *Service) getTable(ctx context.Context, tx Transaction, in *api.GetTableInput) (*api.GetTableOutput, error) {
	b, n, name := value(in.TableBucketARN), value(in.Namespace), value(in.Name)
	if in.TableArn != nil {
		if b != "" || n != "" || name != "" {
			return nil, invalid("Specify tableArn or table bucket, namespace and name")
		}
		arn := value(in.TableArn)
		i := strings.LastIndex(arn, "/table/")
		if i < 0 {
			return nil, invalid("Invalid table ARN")
		}
		b = arn[:i]
		if !strings.HasPrefix(b, bucketARN(scopeFor(ctx), "")) {
			return nil, ErrNotFound
		}
		rows, e := tx.Tables(scopeFor(ctx), b)
		if e != nil {
			return nil, e
		}
		for _, v := range rows {
			if v.ARN == arn {
				n, name = v.Namespace, v.Name
				break
			}
		}
	}
	v, e := s.table(ctx, tx, "GetTable", b, n, name)
	if e != nil {
		return nil, e
	}
	ns, e := tx.Namespace(v.Scope, b, n)
	if e != nil {
		return nil, e
	}
	bucket, e := tx.Bucket(v.Scope, b)
	if e != nil {
		return nil, e
	}
	out := &api.GetTableOutput{CreatedAt: &v.Created, ModifiedAt: &v.Modified, Namespace: api.NamespaceList{api.NamespaceName(v.Namespace)}}
	text(&out.CreatedBy, v.AccountID)
	text(&out.ModifiedBy, v.AccountID)
	text(&out.OwnerAccountId, v.AccountID)
	text(&out.Format, "ICEBERG")
	text(&out.Name, v.Name)
	text(&out.NamespaceId, ns.ID)
	text(&out.TableBucketId, bucket.ID)
	text(&out.TableARN, v.ARN)
	text(&out.Type, "customer")
	text(&out.VersionToken, v.VersionToken)
	text(&out.WarehouseLocation, v.Warehouse)
	if v.MetadataLocation != "" {
		text(&out.MetadataLocation, v.MetadataLocation)
	}
	return out, nil
}
func (s *Service) listTables(ctx context.Context, tx Transaction, in *api.ListTablesInput) (*api.ListTablesOutput, error) {
	b, e := s.bucket(ctx, tx, "ListTables", value(in.TableBucketARN), namespaceAuthorizationContext(value(in.Namespace)))
	if e != nil {
		return nil, e
	}
	binding := "tables/" + b.ARN + "/" + value(in.Namespace) + "/" + value(in.Prefix)
	after, n, e := page(binding, in.ContinuationToken, in.MaxTables)
	if e != nil {
		return nil, e
	}
	rows, e := tx.Tables(b.Scope, b.ARN)
	if e != nil {
		return nil, e
	}
	out := &api.ListTablesOutput{Tables: api.TableSummaryList{}}
	last := ""
	for _, v := range rows {
		cursor := v.Namespace + "/" + v.Name
		if cursor <= after || !strings.HasPrefix(v.Name, value(in.Prefix)) || (in.Namespace != nil && v.Namespace != value(in.Namespace)) {
			continue
		}
		if len(out.Tables) == n {
			out.ContinuationToken = next(binding, last)
			break
		}
		ns, e := tx.Namespace(v.Scope, v.BucketARN, v.Namespace)
		if e != nil {
			return nil, e
		}
		item := api.TableSummary{CreatedAt: &v.Created, ModifiedAt: &v.Modified, Namespace: api.NamespaceList{api.NamespaceName(v.Namespace)}}
		text(&item.Name, v.Name)
		text(&item.TableARN, v.ARN)
		text(&item.Type, "customer")
		text(&item.NamespaceId, ns.ID)
		text(&item.TableBucketId, b.ID)
		out.Tables = append(out.Tables, item)
		last = cursor
	}
	return out, nil
}
func (s *Service) getTableMetadataLocation(ctx context.Context, tx Transaction, in *api.GetTableMetadataLocationInput) (*api.GetTableMetadataLocationOutput, error) {
	v, e := s.table(ctx, tx, "GetTableMetadataLocation", value(in.TableBucketARN), value(in.Namespace), value(in.Name))
	if e != nil {
		return nil, e
	}
	out := &api.GetTableMetadataLocationOutput{}
	text(&out.WarehouseLocation, v.Warehouse)
	text(&out.VersionToken, v.VersionToken)
	if v.MetadataLocation != "" {
		text(&out.MetadataLocation, v.MetadataLocation)
	}
	return out, nil
}
func (s *Service) updateTableMetadataLocation(ctx context.Context, tx Transaction, in *api.UpdateTableMetadataLocationInput, prepared *PreparedTableMetadataUpdate) (*api.UpdateTableMetadataLocationOutput, error) {
	v, e := s.table(ctx, tx, "UpdateTableMetadataLocation", value(in.TableBucketARN), value(in.Namespace), value(in.Name))
	if e != nil {
		return nil, e
	}
	if _, e = metadataUpdateKey(v, in); e != nil {
		return nil, e
	}
	location := value(in.MetadataLocation)
	if prepared == nil || prepared.scope != v.Scope || prepared.arn != v.ARN || prepared.bucket != v.BucketARN || prepared.namespace != v.Namespace || prepared.name != v.Name || prepared.token != v.VersionToken || prepared.location != location {
		return nil, invalid("Prepared metadata does not match this table update")
	}
	v.MetadataLocation = location
	v.VersionToken = uuid.NewString()
	v.Modified = s.clock.Now().UTC()
	if e = tx.PutTable(v); e != nil {
		return nil, e
	}
	if e = tx.PutTableColumns(v.Scope, v.ARN, prepared.columns); e != nil {
		return nil, e
	}
	out := &api.UpdateTableMetadataLocationOutput{Namespace: api.NamespaceList{api.NamespaceName(v.Namespace)}}
	text(&out.Name, v.Name)
	text(&out.TableARN, v.ARN)
	text(&out.MetadataLocation, v.MetadataLocation)
	text(&out.VersionToken, v.VersionToken)
	return out, nil
}
func (s *Service) renameTable(ctx context.Context, tx Transaction, in *api.RenameTableInput) (*api.RenameTableOutput, error) {
	v, e := s.table(ctx, tx, "RenameTable", value(in.TableBucketARN), value(in.Namespace), value(in.Name))
	if e != nil {
		return nil, e
	}
	if in.VersionToken != nil && value(in.VersionToken) != v.VersionToken {
		return nil, conflict("The table version token is stale")
	}
	n, name := v.Namespace, v.Name
	if in.NewName != nil {
		name = value(in.NewName)
	}
	if in.NewNamespaceName != nil {
		n = value(in.NewNamespaceName)
	}
	if !namePattern.MatchString(n) || !namePattern.MatchString(name) {
		return nil, invalid("Invalid destination name")
	}
	if _, e = tx.Namespace(v.Scope, v.BucketARN, n); e != nil {
		return nil, e
	}
	if n != v.Namespace || name != v.Name {
		if _, e = tx.Table(v.Scope, v.BucketARN, n, name); e == nil {
			return nil, conflict("Destination table already exists")
		} else if !errors.Is(e, ErrNotFound) {
			return nil, e
		}
	}
	v.Name = name
	v.Namespace = n
	v.VersionToken = uuid.NewString()
	v.Modified = s.clock.Now().UTC()
	return &api.RenameTableOutput{}, tx.PutTable(v)
}
