package stackd_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3tables"
	"github.com/aws/smithy-go"
)

// The documented Glue creation shape must reach the real owner through public
// authentication, typed persistence and event publication, including after reopen.
// https://docs.aws.amazon.com/lake-formation/latest/dg/create-databases-tables-s3-catalog.html
func TestS3TablesGlueSDKManagedCreationSurvivesReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture, reopen := newIcebergRESTFixture(t, backend)
			clientFor := func() *s3tables.Client {
				return s3tables.New(s3tables.Options{Region: icebergRESTRegion, BaseEndpoint: aws.String(fixture.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: fixture.server.Client(), RetryMaxAttempts: 1})
			}
			owner := clientFor()
			bucket, err := owner.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("sdk-glue-owner")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = owner.CreateNamespace(t.Context(), &s3tables.CreateNamespaceInput{TableBucketARN: bucket.Arn, Namespace: []string{"analytics"}}); err != nil {
				t.Fatal(err)
			}
			parent := icebergRESTAccount + ":s3tablescatalog"
			mounted := parent + "/sdk-glue-owner"
			identifier := "arn:aws:s3tables:" + icebergRESTRegion + ":" + icebergRESTAccount + ":bucket/*"
			if _, err = fixture.glue.CreateCatalog(t.Context(), &glue.CreateCatalogInput{Name: aws.String("s3tablescatalog"), CatalogInput: &gluetypes.CatalogInput{FederatedCatalog: &gluetypes.FederatedCatalog{ConnectionName: aws.String("aws:s3tables"), Identifier: aws.String(identifier)}}}); err != nil {
				t.Fatal(err)
			}
			assertFederation := func(want string) {
				t.Helper()
				out, err := fixture.glue.GetCatalog(t.Context(), &glue.GetCatalogInput{CatalogId: aws.String(parent)})
				if err != nil {
					t.Fatal(err)
				}
				if out.Catalog == nil || out.Catalog.FederatedCatalog == nil || aws.ToString(out.Catalog.FederatedCatalog.Identifier) != want || aws.ToString(out.Catalog.FederatedCatalog.ConnectionName) != "aws:s3tables" {
					t.Fatalf("public parent lost its authoritative federation: %#v", out.Catalog)
				}
				if _, err = fixture.glue.GetCatalog(t.Context(), &glue.GetCatalogInput{CatalogId: aws.String(mounted)}); err != nil {
					t.Fatalf("mounted owner is not discoverable: %v", err)
				}
			}
			createManaged := func(name string) string {
				t.Helper()
				_, err := fixture.glue.CreateTable(t.Context(), &glue.CreateTableInput{CatalogId: aws.String(mounted), DatabaseName: aws.String("analytics"), TableInput: &gluetypes.TableInput{Name: aws.String(name), Parameters: map[string]string{"format": "ICEBERG"}, StorageDescriptor: &gluetypes.StorageDescriptor{Columns: []gluetypes.Column{{Name: aws.String("id"), Type: aws.String("bigint"), Parameters: map[string]string{"required": "true"}}}}}})
				if err != nil {
					t.Fatalf("documented Glue managed creation failed: %v", err)
				}
				head, err := owner.GetTableMetadataLocation(t.Context(), &s3tables.GetTableMetadataLocationInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				projected, err := fixture.glue.GetTable(t.Context(), &glue.GetTableInput{CatalogId: aws.String(mounted), DatabaseName: aws.String("analytics"), Name: aws.String(name)})
				if err != nil {
					t.Fatal(err)
				}
				if projected.Table == nil || projected.Table.Parameters["metadata_location"] != aws.ToString(head.MetadataLocation) || aws.ToString(projected.Table.VersionId) != aws.ToString(head.VersionToken) || projected.Table.StorageDescriptor == nil || len(projected.Table.StorageDescriptor.Columns) != 1 || aws.ToString(projected.Table.StorageDescriptor.Columns[0].Type) != "bigint" {
					t.Fatalf("Glue projection diverged from real managed head/schema: %#v", projected.Table)
				}
				location, err := url.Parse(aws.ToString(head.MetadataLocation))
				if err != nil {
					t.Fatal(err)
				}
				object, err := fixture.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(location.Host), Key: aws.String(strings.TrimPrefix(location.Path, "/"))})
				if err != nil {
					t.Fatal(err)
				}
				data, readErr := io.ReadAll(object.Body)
				closeErr := object.Body.Close()
				if readErr != nil || closeErr != nil {
					t.Fatalf("read authoritative metadata: %v, close: %v", readErr, closeErr)
				}
				var metadata struct {
					Location string `json:"location"`
					Schemas  []struct {
						Fields []struct {
							Name     string `json:"name"`
							Type     string `json:"type"`
							Required bool   `json:"required"`
						} `json:"fields"`
					} `json:"schemas"`
				}
				if err = json.Unmarshal(data, &metadata); err != nil {
					t.Fatal(err)
				}
				if metadata.Location != aws.ToString(head.WarehouseLocation) || len(metadata.Schemas) != 1 || len(metadata.Schemas[0].Fields) != 1 || metadata.Schemas[0].Fields[0].Name != "id" || metadata.Schemas[0].Fields[0].Type != "long" || !metadata.Schemas[0].Fields[0].Required {
					t.Fatalf("Glue creation did not materialize its typed owner schema: %s", data)
				}
				return location.String()
			}
			assertFederation(identifier)
			firstLocation := createManaged("before_reopen")
			fixture = reopen()
			owner = clientFor()
			assertFederation(identifier)
			// Exercise the ON CONFLICT update path, not only initial persistence.
			identifier = aws.ToString(bucket.Arn)
			if _, err = fixture.glue.UpdateCatalog(t.Context(), &glue.UpdateCatalogInput{CatalogId: aws.String(parent), CatalogInput: &gluetypes.CatalogInput{FederatedCatalog: &gluetypes.FederatedCatalog{ConnectionName: aws.String("aws:s3tables"), Identifier: aws.String(identifier)}}}); err != nil {
				t.Fatal(err)
			}
			fixture = reopen()
			owner = clientFor()
			assertFederation(identifier)
			createManaged("after_reopen")

			user := "managed-catalog-reader"
			if _, err = fixture.iam.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)}); err != nil {
				t.Fatal(err)
			}
			key, err := fixture.iam.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: aws.String(user)})
			if err != nil {
				t.Fatal(err)
			}
			putPolicy := func(document string) {
				t.Helper()
				if _, err := fixture.iam.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String("current-owner-access"), PolicyDocument: aws.String(document)}); err != nil {
					t.Fatal(err)
				}
			}
			putPolicy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["glue:*","s3tables:*"],"Resource":"*"}]}`)
			reader := glue.New(glue.Options{Region: icebergRESTRegion, BaseEndpoint: aws.String(fixture.server.URL), Credentials: credentials.NewStaticCredentialsProvider(aws.ToString(key.AccessKey.AccessKeyId), aws.ToString(key.AccessKey.SecretAccessKey), ""), HTTPClient: fixture.server.Client(), RetryMaxAttempts: 1})
			readInput := &glue.GetTableInput{CatalogId: aws.String(mounted), DatabaseName: aws.String("analytics"), Name: aws.String("before_reopen")}
			if _, err = reader.GetTable(t.Context(), readInput); err != nil {
				t.Fatal(err)
			}
			putPolicy(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["glue:*","s3tables:*"],"Resource":"*"},{"Effect":"Deny","Action":"glue:GetTable","Resource":"*"}]}`)
			_, err = reader.GetTable(t.Context(), readInput)
			var denied smithy.APIError
			if !errors.As(err, &denied) || denied.ErrorCode() != "AccessDeniedException" {
				t.Fatalf("current Glue IAM revocation must deny the managed projection: %v", err)
			}
			foreign := glue.New(glue.Options{Region: "us-west-2", BaseEndpoint: aws.String(fixture.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: fixture.server.Client(), RetryMaxAttempts: 1})
			_, err = foreign.GetTable(t.Context(), readInput)
			var missing *gluetypes.EntityNotFoundException
			if !errors.As(err, &missing) {
				t.Fatalf("foreign Region exposed the mounted table: %v", err)
			}
			for _, name := range []string{"before_reopen", "after_reopen"} {
				if _, err = fixture.glue.DeleteTable(t.Context(), &glue.DeleteTableInput{CatalogId: aws.String(mounted), DatabaseName: aws.String("analytics"), Name: aws.String(name)}); err != nil {
					t.Fatal(err)
				}
			}
			deleted, err := url.Parse(firstLocation)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := fixture.s3.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(deleted.Host), Key: aws.String(strings.TrimPrefix(deleted.Path, "/"))}); err == nil {
				out.Body.Close()
				t.Fatal("deleted managed warehouse remained readable through public S3")
			}
			if _, err = owner.DeleteNamespace(t.Context(), &s3tables.DeleteNamespaceInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics")}); err != nil {
				t.Fatal(err)
			}
			if _, err = owner.DeleteTableBucket(t.Context(), &s3tables.DeleteTableBucketInput{TableBucketARN: bucket.Arn}); err != nil {
				t.Fatal(err)
			}
			if _, err = fixture.glue.DeleteCatalog(t.Context(), &glue.DeleteCatalogInput{CatalogId: aws.String(parent)}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
