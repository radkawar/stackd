package cloudformation

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestResourceSchemaAdmission(t *testing.T) {
	cases := []struct {
		name, resource, message string
		properties              Properties
	}{
		{"unknown property", "AWS::SQS::Queue", "no property", Properties{"VisiblityTimeout": 30}},
		{"read-only identifier", "AWS::SQS::Queue", "read-only", Properties{"QueueUrl": "https://sqs.us-east-1.amazonaws.com/111111111111/q"}},
		{"nested read-only", "AWS::S3::Bucket", "read-only", Properties{"MetadataTableConfiguration": map[string]any{"S3TablesDestination": map[string]any{"TableArn": "arn:example"}}}},
		{"nested unknown", "AWS::S3::Bucket", "no property", Properties{"VersioningConfiguration": map[string]any{"Statuz": "Enabled"}}},
		{"nested required", "AWS::SQS::Queue", "requires property", Properties{"Tags": []any{map[string]any{"Key": "purpose"}}}},
		{"required property", "AWS::SNS::Subscription", "requires property", Properties{"Endpoint": "queue"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateResourceProperties(tc.resource, tc.properties)
			if err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("admission error = %v, want %s", err, tc.message)
			}
		})
	}
}

func TestResourceIdentifierUsesRegistryPrimaryProperties(t *testing.T) {
	url := "https://sqs.us-east-1.amazonaws.com/111111111111/example"
	got, err := ResourceIdentifier("AWS::SQS::Queue", Properties{"QueueName": "example", "QueueUrl": url})
	if err != nil || got != url {
		t.Fatalf("queue identifier = %q, %v", got, err)
	}
	if _, err := ResourceIdentifier("AWS::SQS::Queue", Properties{"QueueName": "example"}); err == nil {
		t.Fatal("queue name is not the registry primary identifier")
	}
	got, err = ResourceIdentifier("AWS::Lambda::Permission", Properties{"FunctionName": "function", "Id": "statement"})
	if err != nil || got != "function|statement" {
		t.Fatalf("compound identifier = %q, %v", got, err)
	}
}

func TestResourceUpdateRejectsCreateOnlyChanges(t *testing.T) {
	before := Properties{"QueueName": "example", "VisibilityTimeout": 30}
	for _, after := range []Properties{{"QueueName": "renamed", "VisibilityTimeout": 30}, {"VisibilityTimeout": 30}, {"QueueName": "example", "FifoQueue": true}} {
		if err := ValidateResourceUpdate("AWS::SQS::Queue", before, after); !errors.Is(err, ErrCreateOnly) {
			t.Fatalf("immutable update error = %v", err)
		}
	}
	if err := ValidateResourceUpdate("AWS::SQS::Queue", before, Properties{"QueueName": "example", "VisibilityTimeout": 45}); err != nil {
		t.Fatal(err)
	}
	before = Properties{"FunctionName": "f", "Role": "role", "Code": map[string]any{"ZipFile": "code"}, "TenancyConfig": map[string]any{"TenantIsolationMode": "PER_TENANT"}}
	after := WritableResourceProperties("AWS::Lambda::Function", before)
	after["TenancyConfig"].(map[string]any)["TenantIsolationMode"] = "changed"
	if err := ValidateResourceUpdate("AWS::Lambda::Function", before, after); !errors.Is(err, ErrCreateOnly) {
		t.Fatalf("nested immutable update error = %v", err)
	}
}

func TestResourcePatchReadOnlyAndImmutableBoundaries(t *testing.T) {
	for _, path := range []string{"/Arn", "/MetadataTableConfiguration/S3TablesDestination/TableArn", "/MetadataTableConfiguration", ""} {
		if err := ValidateResourcePatchPath("AWS::S3::Bucket", path); err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Fatalf("patch %q error = %v", path, err)
		}
	}
	if err := ValidateResourcePatchPath("AWS::SQS::Queue", "/QueueName"); !errors.Is(err, ErrCreateOnly) {
		t.Fatalf("immutable patch error = %v", err)
	}
	if err := ValidateResourcePatchPath("AWS::S3::Bucket", "/MetadataTableConfiguration/S3TablesDestination/TableBucketArn"); err != nil {
		t.Fatal(err)
	}
}

func TestWritableResourcePropertiesRetainsNestedDesiredState(t *testing.T) {
	before := Properties{"BucketName": "example", "Arn": "arn:bucket", "MetadataTableConfiguration": map[string]any{"S3TablesDestination": map[string]any{"TableArn": "arn:table", "TableBucketArn": "arn:table-bucket"}}}
	want := Properties{"BucketName": "example", "MetadataTableConfiguration": map[string]any{"S3TablesDestination": map[string]any{"TableBucketArn": "arn:table-bucket"}}}
	after := WritableResourceProperties("AWS::S3::Bucket", before)
	if !reflect.DeepEqual(after, want) {
		t.Fatalf("writable model = %#v", after)
	}
	after["MetadataTableConfiguration"].(map[string]any)["S3TablesDestination"].(map[string]any)["TableBucketArn"] = "changed"
	original := before["MetadataTableConfiguration"].(map[string]any)["S3TablesDestination"].(map[string]any)
	if original["TableArn"] != "arn:table" || original["TableBucketArn"] != "arn:table-bucket" || before["Arn"] != "arn:bucket" {
		t.Fatal("writable model changed owner observations")
	}
}
