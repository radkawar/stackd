package glue

import (
	"context"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/glue"
	tables "stackd/internal/awsapi/s3tables"
	"stackd/internal/awswire"
	managed "stackd/internal/services/s3tables"
)

// S3Tables is the authoritative metadata and data owner, not a replica. Prepared
// publication separates external immutable metadata reads/writes from the
// shared resource transaction and rechecks current IAM and token on publication.
// https://docs.aws.amazon.com/glue/latest/dg/enable-s3-tables-catalog-integration.html
// https://docs.aws.amazon.com/athena/latest/ug/gdc-register-s3-table-bucket-cat.html
// https://docs.aws.amazon.com/glue/latest/dg/s3tables-catalog-prerequisites.html
type S3Tables interface {
	ListTableBuckets(context.Context, *tables.ListTableBucketsInput) (*tables.ListTableBucketsOutput, *awswire.Error)
	GetTableBucket(context.Context, *tables.GetTableBucketInput) (*tables.GetTableBucketOutput, *awswire.Error)
	ListNamespaces(context.Context, *tables.ListNamespacesInput) (*tables.ListNamespacesOutput, *awswire.Error)
	GetNamespace(context.Context, *tables.GetNamespaceInput) (*tables.GetNamespaceOutput, *awswire.Error)
	CreateNamespace(context.Context, *tables.CreateNamespaceInput) (*tables.CreateNamespaceOutput, *awswire.Error)
	DeleteNamespace(context.Context, *tables.DeleteNamespaceInput) (*tables.DeleteNamespaceOutput, *awswire.Error)
	ListTables(context.Context, *tables.ListTablesInput) (*tables.ListTablesOutput, *awswire.Error)
	GetTable(context.Context, *tables.GetTableInput) (*tables.GetTableOutput, *awswire.Error)
	CreateTable(context.Context, *tables.CreateTableInput) (*tables.CreateTableOutput, *awswire.Error)
	DeleteTable(context.Context, *tables.DeleteTableInput) (*tables.DeleteTableOutput, *awswire.Error)
	GetTableMetadataLocation(context.Context, *tables.GetTableMetadataLocationInput) (*tables.GetTableMetadataLocationOutput, *awswire.Error)
	UpdateTableMetadataLocation(context.Context, *tables.UpdateTableMetadataLocationInput) (*tables.UpdateTableMetadataLocationOutput, *awswire.Error)
	Read(context.Context, string) ([]byte, error)
	Write(context.Context, string, []byte) error
	TableColumns(context.Context, string, string, string) ([]managed.Column, *awswire.Error)
	PrepareTableCreate(context.Context, *tables.CreateTableInput) (*managed.PreparedTableCreate, *awswire.Error)
	PublishTableCreate(context.Context, *tables.CreateTableInput, *managed.PreparedTableCreate) (*tables.CreateTableOutput, *awswire.Error)
	DiscardTableCreate(context.Context, *managed.PreparedTableCreate) error
	PrepareTableMetadataUpdate(context.Context, *tables.UpdateTableMetadataLocationInput) (*managed.PreparedTableMetadataUpdate, *awswire.Error)
	PublishTableMetadataUpdate(context.Context, *tables.UpdateTableMetadataLocationInput, *managed.PreparedTableMetadataUpdate) (*tables.UpdateTableMetadataLocationOutput, *awswire.Error)
}

func tableBucketPrefix(scope Scope) string {
	return "arn:" + scope.Partition + ":s3tables:" + scope.Region + ":" + scope.AccountID + ":bucket/"
}

func (s *Service) validateFederatedCatalog(ctx context.Context, tx Reader, key CatalogKey, federation *api.FederatedCatalog) error {
	if federation == nil {
		return nil
	}
	if value(federation.ConnectionName) != "aws:s3tables" {
		return unsupported("Federated catalogs require the aws:s3tables connection.")
	}
	scope := scopeFor(ctx)
	identifier := value(federation.Identifier)
	bucket, ok := strings.CutPrefix(identifier, tableBucketPrefix(scope))
	if key.Scope != scope || !ok {
		return failure("AccessDeniedException", "S3 Tables federation must use the current account, Region and partition.")
	}
	if bucket == "" || strings.ContainsAny(bucket, "/:") || bucket != "*" && strings.ContainsAny(bucket, "*?") {
		return failure("InvalidInputException", "FederatedCatalog.Identifier must identify a table bucket or bucket/*.")
	}
	if err := s.authorize(ctx, tx, "passConnection", scope, ResourceKey{Scope: scope, Name: "aws:s3tables"}.ARN("connection"), nil); err != nil {
		return err
	}
	if s.s3Tables == nil {
		return unsupported("The S3 Tables owner is not configured.")
	}
	if bucket == "*" {
		_, rejected := s.s3Tables.ListTableBuckets(ctx, &tables.ListTableBucketsInput{MaxBuckets: new(tables.ListTableBucketsLimit(1))})
		return federationError(rejected)
	}
	_, rejected := s.s3Tables.GetTableBucket(ctx, &tables.GetTableBucketInput{TableBucketARN: new(tables.TableBucketARN(identifier))})
	return federationError(rejected)
}

func federationError(rejected *awswire.Error) error {
	if rejected == nil {
		return nil
	}
	switch rejected.Code {
	case "NotFoundException":
		return failure("EntityNotFoundException", rejected.Message)
	case "ConflictException":
		return failure("ConcurrentModificationException", rejected.Message)
	case "BadRequestException":
		return failure("InvalidInputException", rejected.Message)
	case "ForbiddenException", "AccessDeniedException", "AccessDenied":
		return failure("AccessDeniedException", rejected.Message)
	default:
		return wireError(rejected)
	}
}

// mountedBucket resolves the current bucket on every call; no child catalog,
// database or table aliases are stored in Glue.
func (s *Service) mountedBucket(ctx context.Context, tx Reader, key CatalogKey) (string, bool, error) {
	parentID, name, ok := splitCatalogChild(key.CatalogID)
	if !ok {
		return "", false, nil
	}
	parent := key
	parent.CatalogID = parentID
	row, err := tx.Catalog(parent)
	if errors.Is(err, ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	federation := row.Catalog.FederatedCatalog
	if federation == nil || value(federation.ConnectionName) != "aws:s3tables" {
		return "", false, nil
	}
	if key.Scope != scopeFor(ctx) {
		return "", true, failure("AccessDeniedException", "Foreign S3 Tables catalogs are not accessible through this integration.")
	}
	bucketARN := tableBucketPrefix(key.Scope) + name
	identifier := value(federation.Identifier)
	if identifier != tableBucketPrefix(key.Scope)+"*" && identifier != bucketARN {
		return "", true, ErrNotFound
	}
	if s.s3Tables == nil {
		return "", true, unsupported("The S3 Tables owner is not configured.")
	}
	_, rejected := s.s3Tables.GetTableBucket(ctx, &tables.GetTableBucketInput{TableBucketARN: new(tables.TableBucketARN(bucketARN))})
	return bucketARN, true, federationError(rejected)
}

func splitCatalogChild(id string) (string, string, bool) {
	index := strings.LastIndexByte(id, '/')
	if index < 0 || index == len(id)-1 || !strings.Contains(id[:index], ":") {
		return "", "", false
	}
	return id[:index], id[index+1:], true
}

func mountedCatalog(key CatalogKey, bucket *tables.GetTableBucketOutput) CatalogRecord {
	_, name, _ := splitCatalogChild(key.CatalogID)
	return CatalogRecord{Key: key, Catalog: api.Catalog{Name: new(api.CatalogNameString(name)), CatalogId: new(api.CatalogIdString(key.CatalogID)), ResourceArn: new(api.ResourceArnString(key.ARN())), CreateTime: bucket.CreatedAt, FederatedCatalog: &api.FederatedCatalog{Identifier: new(api.FederationIdentifier(value(bucket.Arn))), ConnectionName: new(api.NameString("aws:s3tables"))}}}
}

func (s *Service) federatedCatalogChildren(ctx context.Context, tx Reader, parent CatalogRecord) ([]CatalogRecord, error) {
	federation := parent.Catalog.FederatedCatalog
	if federation == nil || value(federation.ConnectionName) != "aws:s3tables" {
		return nil, nil
	}
	if err := s.authorizeCatalog(ctx, tx, "GetCatalogs", parent.Key); err != nil {
		if wireError(err).Code == "AccessDeniedException" {
			return nil, nil
		}
		return nil, err
	}
	if parent.Key.Scope != scopeFor(ctx) {
		return nil, failure("AccessDeniedException", "Foreign S3 Tables catalogs are not accessible through this integration.")
	}
	if s.s3Tables == nil {
		return nil, unsupported("The S3 Tables owner is not configured.")
	}
	identifier := value(federation.Identifier)
	var buckets tables.TableBucketSummaryList
	if identifier != tableBucketPrefix(parent.Key.Scope)+"*" {
		bucket, rejected := s.s3Tables.GetTableBucket(ctx, &tables.GetTableBucketInput{TableBucketARN: new(tables.TableBucketARN(identifier))})
		if rejected != nil {
			return nil, federationError(rejected)
		}
		buckets = append(buckets, tables.TableBucketSummary{Arn: bucket.Arn, Name: bucket.Name, CreatedAt: bucket.CreatedAt, OwnerAccountId: bucket.OwnerAccountId})
	} else {
		request := &tables.ListTableBucketsInput{}
		for {
			page, rejected := s.s3Tables.ListTableBuckets(ctx, request)
			if rejected != nil {
				return nil, federationError(rejected)
			}
			buckets = append(buckets, page.TableBuckets...)
			request.ContinuationToken = page.ContinuationToken
			if value(request.ContinuationToken) == "" {
				break
			}
		}
	}
	out := make([]CatalogRecord, 0, len(buckets))
	for _, bucket := range buckets {
		if value(bucket.OwnerAccountId) != parent.Key.AccountID || value(bucket.Arn) != tableBucketPrefix(parent.Key.Scope)+value(bucket.Name) {
			continue
		}
		key := parent.Key
		key.CatalogID += "/" + value(bucket.Name)
		out = append(out, mountedCatalog(key, &tables.GetTableBucketOutput{Arn: bucket.Arn, Name: bucket.Name, CreatedAt: bucket.CreatedAt}))
	}
	slices.SortFunc(out, func(a, b CatalogRecord) int { return strings.Compare(a.Key.CatalogID, b.Key.CatalogID) })
	return out, nil
}
