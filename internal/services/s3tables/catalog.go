package s3tables

import (
	"context"
	"errors"
	"strings"

	api "stackd/internal/awsapi/s3tables"

	"github.com/google/uuid"
)

func (s *Service) createTableBucket(ctx context.Context, tx Transaction, in *api.CreateTableBucketInput) (*api.CreateTableBucketOutput, error) {
	sc := scopeFor(ctx)
	name := value(in.Name)
	if !bucketPattern.MatchString(name) {
		return nil, invalid("Invalid table bucket name")
	}
	arn := bucketARN(sc, name)
	if e := s.authorize(ctx, "CreateTableBucket", arn, nil); e != nil {
		return nil, e
	}
	if in.EncryptionConfiguration != nil || in.StorageClassConfiguration != nil || len(in.Tags) != 0 {
		return nil, invalid("Explicit encryption, storage class and tags are not supported")
	}
	if _, e := tx.Bucket(sc, arn); e == nil {
		return nil, conflict("Table bucket already exists")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	row := Bucket{Scope: sc, Name: name, ARN: arn, ID: uuid.NewString(), Created: s.clock.Now().UTC()}
	if e := tx.PutBucket(row); e != nil {
		return nil, e
	}
	out := &api.CreateTableBucketOutput{}
	text(&out.Arn, arn)
	return out, nil
}
func (s *Service) getTableBucket(ctx context.Context, tx Transaction, in *api.GetTableBucketInput) (*api.GetTableBucketOutput, error) {
	v, e := s.bucket(ctx, tx, "GetTableBucket", value(in.TableBucketARN), nil)
	if e != nil {
		return nil, e
	}
	out := &api.GetTableBucketOutput{CreatedAt: &v.Created}
	text(&out.Arn, v.ARN)
	text(&out.Name, v.Name)
	text(&out.OwnerAccountId, v.AccountID)
	text(&out.TableBucketId, v.ID)
	text(&out.Type, "customer")
	return out, nil
}
func (s *Service) listTableBuckets(ctx context.Context, tx Transaction, in *api.ListTableBucketsInput) (*api.ListTableBucketsOutput, error) {
	sc := scopeFor(ctx)
	if e := s.authorize(ctx, "ListTableBuckets", "*", nil); e != nil {
		return nil, e
	}
	binding := "buckets/" + bucketARN(sc, "") + "/" + value(in.Prefix) + "/" + value(in.Type)
	after, n, e := page(binding, in.ContinuationToken, in.MaxBuckets)
	if e != nil {
		return nil, e
	}
	rows, e := tx.Buckets(sc)
	if e != nil {
		return nil, e
	}
	out := &api.ListTableBucketsOutput{TableBuckets: api.TableBucketSummaryList{}}
	for _, v := range rows {
		if v.Name <= after || !strings.HasPrefix(v.Name, value(in.Prefix)) || (in.Type != nil && value(in.Type) != "customer") {
			continue
		}
		if len(out.TableBuckets) == n {
			out.ContinuationToken = next(binding, value(out.TableBuckets[n-1].Name))
			break
		}
		item := api.TableBucketSummary{CreatedAt: &v.Created}
		text(&item.Arn, v.ARN)
		text(&item.Name, v.Name)
		text(&item.OwnerAccountId, v.AccountID)
		text(&item.TableBucketId, v.ID)
		text(&item.Type, "customer")
		out.TableBuckets = append(out.TableBuckets, item)
	}
	return out, nil
}
func (s *Service) deleteTableBucket(ctx context.Context, tx Transaction, in *api.DeleteTableBucketInput) (*api.DeleteTableBucketOutput, error) {
	v, e := s.bucket(ctx, tx, "DeleteTableBucket", value(in.TableBucketARN), nil)
	if e != nil {
		return nil, e
	}
	ns, e := tx.Namespaces(v.Scope, v.ARN)
	if e != nil {
		return nil, e
	}
	if len(ns) > 0 {
		return nil, conflict("Table bucket is not empty")
	}
	return &api.DeleteTableBucketOutput{}, tx.DeleteBucket(v.Scope, v.ARN)
}
func (s *Service) createNamespace(ctx context.Context, tx Transaction, in *api.CreateNamespaceInput) (*api.CreateNamespaceOutput, error) {
	v, e := s.bucket(ctx, tx, "CreateNamespace", value(in.TableBucketARN), nil)
	if e != nil {
		return nil, e
	}
	if len(in.Namespace) != 1 || !namePattern.MatchString(string(in.Namespace[0])) {
		return nil, invalid("Exactly one valid namespace is required")
	}
	name := string(in.Namespace[0])
	if _, e = tx.Namespace(v.Scope, v.ARN, name); e == nil {
		return nil, conflict("Namespace already exists")
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	row := Namespace{Scope: v.Scope, BucketARN: v.ARN, Name: name, ID: uuid.NewString(), Created: s.clock.Now().UTC()}
	if e = tx.PutNamespace(row); e != nil {
		return nil, e
	}
	out := &api.CreateNamespaceOutput{Namespace: api.NamespaceList{api.NamespaceName(name)}}
	text(&out.TableBucketARN, v.ARN)
	return out, nil
}
func (s *Service) getNamespace(ctx context.Context, tx Transaction, in *api.GetNamespaceInput) (*api.GetNamespaceOutput, error) {
	v, e := s.bucket(ctx, tx, "GetNamespace", value(in.TableBucketARN), namespaceAuthorizationContext(value(in.Namespace)))
	if e != nil {
		return nil, e
	}
	ns, e := tx.Namespace(v.Scope, v.ARN, value(in.Namespace))
	if e != nil {
		return nil, e
	}
	out := &api.GetNamespaceOutput{CreatedAt: &ns.Created, Namespace: api.NamespaceList{api.NamespaceName(ns.Name)}}
	text(&out.CreatedBy, v.AccountID)
	text(&out.OwnerAccountId, v.AccountID)
	text(&out.NamespaceId, ns.ID)
	text(&out.TableBucketId, v.ID)
	return out, nil
}
func (s *Service) listNamespaces(ctx context.Context, tx Transaction, in *api.ListNamespacesInput) (*api.ListNamespacesOutput, error) {
	v, e := s.bucket(ctx, tx, "ListNamespaces", value(in.TableBucketARN), nil)
	if e != nil {
		return nil, e
	}
	binding := "namespaces/" + v.ARN + "/" + value(in.Prefix)
	after, n, e := page(binding, in.ContinuationToken, in.MaxNamespaces)
	if e != nil {
		return nil, e
	}
	rows, e := tx.Namespaces(v.Scope, v.ARN)
	if e != nil {
		return nil, e
	}
	out := &api.ListNamespacesOutput{Namespaces: api.NamespaceSummaryList{}}
	for _, ns := range rows {
		if ns.Name <= after || !strings.HasPrefix(ns.Name, value(in.Prefix)) {
			continue
		}
		if len(out.Namespaces) == n {
			out.ContinuationToken = next(binding, string(out.Namespaces[n-1].Namespace[0]))
			break
		}
		item := api.NamespaceSummary{CreatedAt: &ns.Created, Namespace: api.NamespaceList{api.NamespaceName(ns.Name)}}
		text(&item.CreatedBy, v.AccountID)
		text(&item.OwnerAccountId, v.AccountID)
		text(&item.NamespaceId, ns.ID)
		text(&item.TableBucketId, v.ID)
		out.Namespaces = append(out.Namespaces, item)
	}
	return out, nil
}
func (s *Service) deleteNamespace(ctx context.Context, tx Transaction, in *api.DeleteNamespaceInput) (*api.DeleteNamespaceOutput, error) {
	v, e := s.bucket(ctx, tx, "DeleteNamespace", value(in.TableBucketARN), namespaceAuthorizationContext(value(in.Namespace)))
	if e != nil {
		return nil, e
	}
	name := value(in.Namespace)
	if _, e = tx.Namespace(v.Scope, v.ARN, name); e != nil {
		return nil, e
	}
	rows, e := tx.Tables(v.Scope, v.ARN)
	if e != nil {
		return nil, e
	}
	for _, t := range rows {
		if t.Namespace == name {
			return nil, conflict("Namespace is not empty")
		}
	}
	return &api.DeleteNamespaceOutput{}, tx.DeleteNamespace(v.Scope, v.ARN, name)
}
