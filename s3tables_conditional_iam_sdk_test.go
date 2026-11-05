package stackd_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3tables"
	tabletypes "github.com/aws/aws-sdk-go-v2/service/s3tables/types"
)

// The service authorization reference defines both condition keys as String.
// Policies and multipart effects must use current typed resource names, including
// when a policy changes or the same immutable table is renamed after initiation.
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3tables.html
func TestS3TablesMultipartSDKConditionalIAMContext(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newMultipartSDKFixture(t, backend)
			const user = "conditional-table-writer"
			if _, err := f.fixture.iam.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)}); err != nil {
				t.Fatal(err)
			}
			access, err := f.fixture.iam.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: aws.String(user)})
			if err != nil {
				t.Fatal(err)
			}
			credential := credentials.NewStaticCredentialsProvider(aws.ToString(access.AccessKey.AccessKeyId), aws.ToString(access.AccessKey.SecretAccessKey), "")
			writer := s3.New(s3.Options{Region: icebergRESTRegion, BaseEndpoint: aws.String(f.fixture.server.URL), UsePathStyle: true, Credentials: credential, HTTPClient: f.fixture.server.Client(), RetryMaxAttempts: 1})
			control := s3tables.New(s3tables.Options{Region: icebergRESTRegion, BaseEndpoint: aws.String(f.fixture.server.URL), Credentials: credential, HTTPClient: f.fixture.server.Client(), RetryMaxAttempts: 1})
			setPolicy := func(denies ...map[string]any) {
				t.Helper()
				statements := []any{map[string]any{"Effect": "Allow", "Action": "s3tables:*", "Resource": "*"}}
				for _, deny := range denies {
					statements = append(statements, deny)
				}
				document, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.fixture.iam.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String("conditional-owner"), PolicyDocument: aws.String(string(document))}); err != nil {
					t.Fatal(err)
				}
			}
			setPolicy()
			key := "data/conditional-publication.parquet"
			previous, err := f.fixture.s3.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), Body: strings.NewReader("previous")})
			if err != nil {
				t.Fatal(err)
			}
			created, err := writer.CreateMultipartUpload(t.Context(), &s3.CreateMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key)})
			if err != nil {
				t.Fatal(err)
			}
			part, err := writer.UploadPart(t.Context(), &s3.UploadPartInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId, PartNumber: aws.Int32(1), Body: strings.NewReader("replacement")})
			if err != nil {
				t.Fatal(err)
			}
			completion := &s3.CompleteMultipartUploadInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId, MultipartUpload: &s3types.CompletedMultipartUpload{Parts: []s3types.CompletedPart{{PartNumber: aws.Int32(1), ETag: part.ETag, ChecksumCRC32: part.ChecksumCRC32}}}}
			for _, operator := range []string{"StringEquals", "ForAnyValue:StringEquals"} {
				condition := map[string]any{"StringEquals": map[string]any{"s3tables:tableName": "events"}}
				if operator == "StringEquals" {
					condition[operator].(map[string]any)["s3tables:namespace"] = "analytics"
				} else {
					// A scalar request value is still one IAM context value; the
					// expected policy set does not make NamespaceList multivalued.
					condition[operator] = map[string]any{"s3tables:namespace": []string{"other", "analytics"}}
				}
				setPolicy(map[string]any{"Effect": "Deny", "Action": []string{"s3tables:PutTableData", "s3tables:GetTable"}, "Resource": "*", "Condition": condition})
				_, err = writer.CompleteMultipartUpload(t.Context(), completion)
				multipartSDKError(t, err, http.StatusForbidden, "AccessDenied")
				f.object(t, key, []byte("previous"), previous.ETag)
				listed, err := writer.ListParts(t.Context(), &s3.ListPartsInput{Bucket: aws.String(f.warehouse), Key: aws.String(key), UploadId: created.UploadId})
				if err != nil || len(listed.Parts) != 1 || aws.ToString(listed.Parts[0].ETag) != aws.ToString(part.ETag) {
					t.Fatalf("conditional write denial changed readable staged parts: %#v %v", listed, err)
				}
				_, err = control.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: f.tableARN})
				multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			}
			rename := func(name string) {
				t.Helper()
				current, err := f.owner.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: f.tableARN})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.owner.RenameTable(t.Context(), &s3tables.RenameTableInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics"), Name: current.Name, NewName: aws.String(name), VersionToken: current.VersionToken}); err != nil {
					t.Fatal(err)
				}
			}
			rename("renamed_events")
			// Keep the exact deny policy: changing the current table name makes
			// it nonmatching, despite the upload having begun under the old name.
			_, err = writer.CompleteMultipartUpload(t.Context(), completion)
			multipartSDKError(t, err, http.StatusPreconditionFailed, "PreconditionFailed")
			f.object(t, key, []byte("previous"), previous.ETag)
			freshKey := key + ".new"
			published, err := writer.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(freshKey), Body: strings.NewReader("after rename")})
			if err != nil {
				t.Fatalf("data authority retained a stale table-name condition: %v", err)
			}
			f.object(t, freshKey, []byte("after rename"), published.ETag)
			if _, err = control.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: f.tableARN}); err != nil {
				t.Fatalf("table control authority retained a stale name: %v", err)
			}
			rename("events")
			setPolicy(map[string]any{"Effect": "Deny", "Action": []string{"s3tables:CreateTable", "s3tables:ListTables", "s3tables:GetNamespace"}, "Resource": "*", "Condition": map[string]any{"StringEquals": map[string]any{"s3tables:namespace": "analytics"}}})
			_, err = control.GetNamespace(t.Context(), &s3tables.GetNamespaceInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics")})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			_, err = control.ListTables(t.Context(), &s3tables.ListTablesInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics")})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			_, err = control.CreateTable(t.Context(), &s3tables.CreateTableInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics"), Name: aws.String("denied_creation"), Format: tabletypes.OpenTableFormatIceberg})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			_, err = f.owner.GetTable(t.Context(), &s3tables.GetTableInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics"), Name: aws.String("denied_creation")})
			multipartSDKError(t, err, http.StatusNotFound, "NotFoundException")
			// ListTables without a namespace request has no namespace condition
			// value: do not fabricate one from the returned table collection.
			if _, err = control.ListTables(t.Context(), &s3tables.ListTablesInput{TableBucketARN: f.bucketARN}); err != nil {
				t.Fatalf("optional namespace scope was manufactured: %v", err)
			}
			f.deleteTable(t)
		})
	}
}
