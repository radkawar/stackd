package stackd_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3tables"
	tabletypes "github.com/aws/aws-sdk-go-v2/service/s3tables/types"
)

// Independently authored from the retained SDK and official S3 Tables contracts:
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_s3Buckets_TagResource.html
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/tagging.html
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/table-tagging.html
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3tables.html
func TestS3TablesTagsSDKLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture, reopen := newIcebergRESTFixture(t, backend)
			client := func(region string) *s3tables.Client {
				return s3tables.New(s3tables.Options{Region: region, BaseEndpoint: aws.String(fixture.server.URL), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: fixture.server.Client(), RetryMaxAttempts: 1})
			}
			owner := client(icebergRESTRegion)
			bucketTags := map[string]string{"project": "bucket", "empty": "", "prefix-value": "aws:allowed", "_ .:/=+@-": "ñ 1_.:/=+@-", strings.Repeat("界", 128): strings.Repeat("é", 256)}
			bucket, err := owner.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("tagged-tables"), Tags: bucketTags})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = owner.CreateNamespace(t.Context(), &s3tables.CreateNamespaceInput{TableBucketARN: bucket.Arn, Namespace: []string{"analytics"}}); err != nil {
				t.Fatal(err)
			}
			table, err := owner.CreateTable(t.Context(), &s3tables.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("events"), Format: tabletypes.OpenTableFormatIceberg, Tags: map[string]string{"project": "table", "Case": "upper", "case": "lower"}, Metadata: &tabletypes.TableMetadataMemberIceberg{Value: tabletypes.IcebergMetadata{Schema: &tabletypes.IcebergSchema{Fields: []tabletypes.SchemaField{{Name: aws.String("id"), Type: aws.String("long")}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			assertTags := func(arn *string, expected map[string]string) {
				t.Helper()
				out, err := owner.ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: arn})
				if err != nil || out == nil || !maps.Equal(out.Tags, expected) {
					t.Fatalf("tags differ: %#v, want %#v: %v", out, expected, err)
				}
				// SDK outputs must not alias durable state.
				out.Tags["project"] = "local-only"
			}
			assertTags(bucket.Arn, bucketTags)
			tableTags := map[string]string{"project": "table", "Case": "upper", "case": "lower"}
			assertTags(table.TableARN, tableTags)
			if _, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: table.TableARN, Tags: map[string]string{"project": "replacement", "new": ""}}); err != nil {
				t.Fatal(err)
			}
			tableTags["project"], tableTags["new"] = "replacement", ""
			assertTags(table.TableARN, tableTags)
			if _, err = owner.UntagResource(t.Context(), &s3tables.UntagResourceInput{ResourceArn: table.TableARN, TagKeys: []string{"Case", "Case", "missing"}}); err != nil {
				t.Fatal(err)
			}
			delete(tableTags, "Case")
			assertTags(table.TableARN, tableTags)
			// Tag mutations do not rotate Iceberg metadata authority/version tokens.
			current, err := owner.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: table.TableARN})
			if err != nil || aws.ToString(current.VersionToken) != aws.ToString(table.VersionToken) {
				t.Fatalf("tags changed table version: %#v %v", current, err)
			}
			if _, err = owner.RenameTable(t.Context(), &s3tables.RenameTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("events"), NewName: aws.String("renamed"), VersionToken: current.VersionToken}); err != nil {
				t.Fatal(err)
			}
			fixture = reopen()
			owner = client(icebergRESTRegion)
			assertTags(bucket.Arn, bucketTags)
			assertTags(table.TableARN, tableTags)

			for _, arn := range []*string{bucket.Arn, table.TableARN} {
				out, err := owner.ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: arn})
				if err != nil {
					t.Fatal(err)
				}
				expected := maps.Clone(out.Tags)
				add := map[string]string{}
				for i := len(expected); i < 50; i++ {
					key := fmt.Sprintf("limit-%02d", i)
					add[key], expected[key] = "value", "value"
				}
				if _, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: arn, Tags: add}); err != nil {
					t.Fatal(err)
				}
				if _, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: arn, Tags: map[string]string{"project": "at-limit"}}); err != nil {
					t.Fatal(err)
				}
				expected["project"] = "at-limit"
				_, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: arn, Tags: map[string]string{"project": "must-roll-back", "overflow": "value"}})
				multipartSDKError(t, err, http.StatusBadRequest, "BadRequestException")
				assertTags(arn, expected)
				for _, invalid := range []map[string]string{{"": "x"}, {strings.Repeat("k", 129): "x"}, {"value": strings.Repeat("v", 257)}, {"aws:owner": "x"}, {"AWS:owner": "x"}, {"bad?key": "x"}, {"valid": "bad!value"}} {
					_, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: arn, Tags: invalid})
					multipartSDKError(t, err, http.StatusBadRequest, "BadRequestException")
					assertTags(arn, expected)
				}
				_, err = owner.UntagResource(t.Context(), &s3tables.UntagResourceInput{ResourceArn: arn, TagKeys: []string{"project", "aws:reserved"}})
				multipartSDKError(t, err, http.StatusBadRequest, "BadRequestException")
				assertTags(arn, expected)
				keys := make([]string, 0, len(expected))
				var unicodeKeys []string
				for key := range expected {
					// The Go signer sorts repeated query values before escaping.
					// AWS rejects that signature when Unicode changes their order;
					// keep Unicode removal separate without weakening verification.
					if strings.ContainsFunc(key, func(r rune) bool { return r > 127 }) {
						unicodeKeys = append(unicodeKeys, key)
					} else {
						keys = append(keys, key)
					}
				}
				for range 2 {
					for _, key := range unicodeKeys {
						if _, err = owner.UntagResource(t.Context(), &s3tables.UntagResourceInput{ResourceArn: arn, TagKeys: []string{key}}); err != nil {
							t.Fatal(err)
						}
					}
					if _, err = owner.UntagResource(t.Context(), &s3tables.UntagResourceInput{ResourceArn: arn, TagKeys: keys}); err != nil {
						t.Fatal(err)
					}
				}
				assertTags(arn, map[string]string{})
				if _, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: arn, Tags: map[string]string{}}); err != nil {
					t.Fatal(err)
				}
			}
			for _, arn := range []string{
				aws.ToString(bucket.Arn) + "/namespace/analytics",
				strings.Replace(aws.ToString(table.TableARN), ":s3tables:", ":s3:", 1),
				strings.Replace(aws.ToString(table.TableARN), "arn:aws:", "arn:aws-cn:", 1),
				strings.Replace(aws.ToString(table.TableARN), ":"+icebergRESTRegion+":", ":eu-west-1:", 1),
				strings.Replace(aws.ToString(table.TableARN), ":"+icebergRESTAccount+":", ":999999999999:", 1),
			} {
				for _, operation := range []string{"list", "tag", "untag"} {
					switch operation {
					case "list":
						_, err = owner.ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: aws.String(arn)})
					case "tag":
						_, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: aws.String(arn), Tags: map[string]string{"foreign": "denied"}})
					case "untag":
						_, err = owner.UntagResource(t.Context(), &s3tables.UntagResourceInput{ResourceArn: aws.String(arn), TagKeys: []string{"project"}})
					}
					multipartSDKError(t, err, http.StatusNotFound, "NotFoundException")
				}
			}
			_, err = client("eu-west-1").ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: table.TableARN})
			multipartSDKError(t, err, http.StatusNotFound, "NotFoundException")
			// Unsupported non-tag create settings must not silently become successes.
			_, err = owner.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("unsupported-encryption"), Tags: map[string]string{"project": "x"}, EncryptionConfiguration: &tabletypes.EncryptionConfiguration{SseAlgorithm: tabletypes.SSEAlgorithmAes256}})
			multipartSDKError(t, err, http.StatusBadRequest, "BadRequestException")
			_, err = owner.CreateTable(t.Context(), &s3tables.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("unsupported"), Format: tabletypes.OpenTableFormatIceberg, Tags: map[string]string{"project": "x"}, EncryptionConfiguration: &tabletypes.EncryptionConfiguration{SseAlgorithm: tabletypes.SSEAlgorithmAes256}})
			multipartSDKError(t, err, http.StatusBadRequest, "BadRequestException")
			_, err = owner.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("unsupported-storage"), Tags: map[string]string{"project": "x"}, StorageClassConfiguration: &tabletypes.StorageClassConfiguration{StorageClass: tabletypes.StorageClassStandard}})
			multipartSDKError(t, err, http.StatusBadRequest, "BadRequestException")
			_, err = owner.CreateTable(t.Context(), &s3tables.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("unsupported_storage"), Format: tabletypes.OpenTableFormatIceberg, Tags: map[string]string{"project": "x"}, StorageClassConfiguration: &tabletypes.StorageClassConfiguration{StorageClass: tabletypes.StorageClassStandard}})
			multipartSDKError(t, err, http.StatusBadRequest, "BadRequestException")
			tooMany := map[string]string{}
			for i := range 51 {
				tooMany[fmt.Sprintf("tag-%d", i)] = "value"
			}
			for _, tags := range []map[string]string{tooMany, {"aws:reserved": "no"}} {
				_, err = owner.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("invalid-create-tags"), Tags: tags})
				multipartSDKError(t, err, http.StatusBadRequest, "BadRequestException")
				_, err = owner.CreateTable(t.Context(), &s3tables.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("invalid_create_tags"), Format: tabletypes.OpenTableFormatIceberg, Tags: tags})
				multipartSDKError(t, err, http.StatusBadRequest, "BadRequestException")
			}

			if _, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: table.TableARN, Tags: map[string]string{"deleted": "old"}}); err != nil {
				t.Fatal(err)
			}
			current, err = owner.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: table.TableARN})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = owner.DeleteTable(t.Context(), &s3tables.DeleteTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("renamed"), VersionToken: current.VersionToken}); err != nil {
				t.Fatal(err)
			}
			replacement, err := owner.CreateTable(t.Context(), &s3tables.CreateTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("renamed"), Format: tabletypes.OpenTableFormatIceberg})
			if err != nil {
				t.Fatal(err)
			}
			assertTags(replacement.TableARN, map[string]string{})
			for _, operation := range []string{"list", "tag", "untag"} {
				switch operation {
				case "list":
					_, err = owner.ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: table.TableARN})
				case "tag":
					_, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: table.TableARN, Tags: map[string]string{"deleted": "no"}})
				case "untag":
					_, err = owner.UntagResource(t.Context(), &s3tables.UntagResourceInput{ResourceArn: table.TableARN, TagKeys: []string{"deleted"}})
				}
				multipartSDKError(t, err, http.StatusNotFound, "NotFoundException")
			}
			if _, err = owner.DeleteTable(t.Context(), &s3tables.DeleteTableInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics"), Name: aws.String("renamed"), VersionToken: replacement.VersionToken}); err != nil {
				t.Fatal(err)
			}
			if _, err = owner.DeleteNamespace(t.Context(), &s3tables.DeleteNamespaceInput{TableBucketARN: bucket.Arn, Namespace: aws.String("analytics")}); err != nil {
				t.Fatal(err)
			}
			if _, err = owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: bucket.Arn, Tags: map[string]string{"deleted": "old"}}); err != nil {
				t.Fatal(err)
			}
			if _, err = owner.DeleteTableBucket(t.Context(), &s3tables.DeleteTableBucketInput{TableBucketARN: bucket.Arn}); err != nil {
				t.Fatal(err)
			}
			_, err = owner.ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: bucket.Arn})
			multipartSDKError(t, err, http.StatusNotFound, "NotFoundException")
			fixture = reopen()
			owner = client(icebergRESTRegion)
			recreated, err := owner.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("tagged-tables")})
			if err != nil {
				t.Fatal(err)
			}
			assertTags(recreated.Arn, map[string]string{})
		})
	}
}

func TestS3TablesTagsSDKCurrentIAMConditions(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newMultipartSDKFixture(t, backend)
			const user = "table-tag-governor"
			if _, err := f.fixture.iam.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(user)}); err != nil {
				t.Fatal(err)
			}
			access, err := f.fixture.iam.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{UserName: aws.String(user)})
			if err != nil {
				t.Fatal(err)
			}
			credential := credentials.NewStaticCredentialsProvider(aws.ToString(access.AccessKey.AccessKeyId), aws.ToString(access.AccessKey.SecretAccessKey), "")
			control := s3tables.New(s3tables.Options{Region: icebergRESTRegion, BaseEndpoint: aws.String(f.fixture.server.URL), Credentials: credential, HTTPClient: f.fixture.server.Client(), RetryMaxAttempts: 1})
			data := s3.New(s3.Options{Region: icebergRESTRegion, BaseEndpoint: aws.String(f.fixture.server.URL), UsePathStyle: true, Credentials: credential, HTTPClient: f.fixture.server.Client(), RetryMaxAttempts: 1})
			setPolicy := func(statements ...map[string]any) {
				t.Helper()
				document, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.fixture.iam.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String("tag-governance"), PolicyDocument: aws.String(string(document))}); err != nil {
					t.Fatal(err)
				}
			}
			allow := map[string]any{"Effect": "Allow", "Action": "s3tables:*", "Resource": "*"}
			setPolicy(map[string]any{"Effect": "Allow", "Action": []string{"s3tables:CreateTable", "s3tables:CreateTableBucket"}, "Resource": "*"})
			_, err = control.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("denied-tagged-bucket"), Tags: map[string]string{"project": "allowed"}})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			_, err = f.owner.GetTableBucket(t.Context(), &s3tables.GetTableBucketInput{TableBucketARN: aws.String(strings.Split(aws.ToString(f.bucketARN), "bucket/")[0] + "bucket/denied-tagged-bucket")})
			multipartSDKError(t, err, http.StatusNotFound, "NotFoundException")
			create := &s3tables.CreateTableInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics"), Name: aws.String("governed"), Format: tabletypes.OpenTableFormatIceberg, Tags: map[string]string{"project": "allowed"}}
			_, err = control.CreateTable(t.Context(), create)
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			_, err = f.owner.GetTable(t.Context(), &s3tables.GetTableInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics"), Name: create.Name})
			multipartSDKError(t, err, http.StatusNotFound, "NotFoundException")
			if _, err = control.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("untagged-permission")}); err != nil {
				t.Fatalf("untagged bucket incorrectly requires TagResource: %v", err)
			}
			if _, err = control.CreateTable(t.Context(), &s3tables.CreateTableInput{TableBucketARN: f.bucketARN, Namespace: aws.String("analytics"), Name: aws.String("untagged_permission"), Format: tabletypes.OpenTableFormatIceberg}); err != nil {
				t.Fatalf("untagged table incorrectly requires TagResource: %v", err)
			}
			// TableBucketTag on CreateTableBucket reads the incoming bucket tags, not
			// a nonexistent old resource or the tags of another table bucket.
			setPolicy(map[string]any{"Effect": "Allow", "Action": []string{"s3tables:CreateTableBucket", "s3tables:TagResource"}, "Resource": "*", "Condition": map[string]any{"StringEquals": map[string]any{"s3tables:TableBucketTag/project": "allowed"}}})
			_, err = control.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("bucket-condition-create"), Tags: map[string]string{"project": "blocked"}})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			if _, err = control.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("bucket-condition-create"), Tags: map[string]string{"project": "allowed"}}); err != nil {
				t.Fatal(err)
			}
			// Creation checks request tags on BOTH CreateTable and its additional
			// TagResource authorization, against the table bucket and new table ARN.
			setPolicy(map[string]any{"Effect": "Allow", "Action": []string{"s3tables:CreateTable", "s3tables:CreateTableBucket", "s3tables:TagResource"}, "Resource": "*", "Condition": map[string]any{"StringEquals": map[string]any{"aws:RequestTag/project": "allowed"}, "ForAllValues:StringEquals": map[string]any{"aws:TagKeys": []string{"project"}}}})
			create.Tags["project"] = "blocked"
			_, err = control.CreateTable(t.Context(), create)
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			create.Tags["project"], create.Tags["unapproved"] = "allowed", "no"
			_, err = control.CreateTable(t.Context(), create)
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			delete(create.Tags, "unapproved")
			created, err := control.CreateTable(t.Context(), create)
			if err != nil {
				t.Fatal(err)
			}
			taggedBucket, err := control.CreateTableBucket(t.Context(), &s3tables.CreateTableBucketInput{Name: aws.String("governed-tags"), Tags: map[string]string{"project": "allowed"}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = control.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: taggedBucket.Arn, Tags: map[string]string{"project": "blocked"}})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			if _, err = control.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: taggedBucket.Arn, Tags: map[string]string{"project": "allowed"}}); err != nil {
				t.Fatal(err)
			}
			setPolicy(allow, map[string]any{"Effect": "Deny", "Action": []string{"s3tables:TagResource", "s3tables:UntagResource"}, "Resource": "*", "Condition": map[string]any{"ForAnyValue:StringEquals": map[string]any{"aws:TagKeys": []string{"protected"}}}})
			_, err = control.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: created.TableARN, Tags: map[string]string{"project": "changed", "protected": "denied"}})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			_, err = control.UntagResource(t.Context(), &s3tables.UntagResourceInput{ResourceArn: created.TableARN, TagKeys: []string{"project", "protected"}})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			tags, err := f.owner.ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: created.TableARN})
			if err != nil || !maps.Equal(tags.Tags, map[string]string{"project": "allowed"}) {
				t.Fatalf("IAM denial mutated tags: %#v %v", tags, err)
			}

			if _, err = f.owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: f.bucketARN, Tags: map[string]string{"project": "bucket", "gate": "closed"}}); err != nil {
				t.Fatal(err)
			}
			if _, err = f.owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: f.tableARN, Tags: map[string]string{"project": "table", "gate": "open"}}); err != nil {
				t.Fatal(err)
			}
			// ResourceTag on table actions never inherits the table bucket's tags.
			setPolicy(allow, map[string]any{"Effect": "Deny", "Action": []string{"s3tables:GetTable", "s3tables:GetTableData", "s3tables:ListTagsForResource", "s3tables:GetTableBucket"}, "Resource": "*", "Condition": map[string]any{"StringEquals": map[string]any{"aws:ResourceTag/project": "bucket"}}})
			if _, err = control.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: f.tableARN}); err != nil {
				t.Fatal(err)
			}
			if _, err = control.ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: f.tableARN}); err != nil {
				t.Fatal(err)
			}
			_, err = control.GetTableBucket(t.Context(), &s3tables.GetTableBucketInput{TableBucketARN: f.bucketARN})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			_, err = control.ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: f.bucketARN})
			multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
			for _, condition := range []string{"aws:ResourceTag/gate", "s3tables:TableBucketTag/gate"} {
				expected := "open"
				if condition == "s3tables:TableBucketTag/gate" {
					expected = "closed"
				}
				setPolicy(allow, map[string]any{"Effect": "Deny", "Action": []string{"s3tables:GetTable", "s3tables:TagResource", "s3tables:UntagResource", "s3tables:ListTagsForResource", "s3tables:PutTableData", "s3tables:GetTableData"}, "Resource": "*", "Condition": map[string]any{"StringEquals": map[string]any{condition: expected}}})
				_, err = control.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: f.tableARN})
				multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
				_, err = control.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: f.tableARN, Tags: map[string]string{"gate": "escape"}})
				multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
				_, err = control.UntagResource(t.Context(), &s3tables.UntagResourceInput{ResourceArn: f.tableARN, TagKeys: []string{"gate"}})
				multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
				_, err = control.ListTagsForResource(t.Context(), &s3tables.ListTagsForResourceInput{ResourceArn: f.tableARN})
				multipartSDKError(t, err, http.StatusForbidden, "ForbiddenException")
				_, err = data.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String("data/governed.parquet"), Body: strings.NewReader("denied")})
				multipartSDKError(t, err, http.StatusForbidden, "AccessDenied")
				_, err = data.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String(f.metadata)})
				multipartSDKError(t, err, http.StatusForbidden, "AccessDenied")
			}
			// Changing the parent tag immediately changes table/data authority, without
			// changing the user's policy or copying the bucket tag into table tags.
			if _, err = f.owner.TagResource(t.Context(), &s3tables.TagResourceInput{ResourceArn: f.bucketARN, Tags: map[string]string{"gate": "released"}}); err != nil {
				t.Fatal(err)
			}
			if _, err = control.GetTable(t.Context(), &s3tables.GetTableInput{TableArn: f.tableARN}); err != nil {
				t.Fatal(err)
			}
			if _, err = data.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(f.warehouse), Key: aws.String("data/governed.parquet"), Body: strings.NewReader("accepted")}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
