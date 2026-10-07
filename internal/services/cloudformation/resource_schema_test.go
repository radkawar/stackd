package cloudformation

import (
	"errors"
	"reflect"
	"testing"
)

func TestResourceSchemaAdmission(t *testing.T) {
	cases := []struct {
		name, resource string
		properties     Properties
	}{
		{"unknown property", "AWS::SQS::Queue", Properties{"VisiblityTimeout": 30}},
		{"read-only identifier", "AWS::SQS::Queue", Properties{"QueueUrl": "https://sqs.us-east-1.amazonaws.com/111111111111/q"}},
		{"nested read-only", "AWS::S3::Bucket", Properties{"MetadataTableConfiguration": map[string]any{"S3TablesDestination": map[string]any{"TableArn": "arn:example"}}}},
		{"nested unknown", "AWS::S3::Bucket", Properties{"VersioningConfiguration": map[string]any{"Statuz": "Enabled"}}},
		{"nested required", "AWS::SQS::Queue", Properties{"Tags": []any{map[string]any{"Key": "purpose"}}}},
		{"required property", "AWS::SNS::Subscription", Properties{"Endpoint": "queue"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateResourceProperties(tc.resource, tc.properties)
			if err == nil {
				t.Fatal("invalid resource properties were admitted")
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
	after, err := WritableResourceProperties("AWS::Lambda::Function", before)
	if err != nil {
		t.Fatal(err)
	}
	after["TenancyConfig"].(map[string]any)["TenantIsolationMode"] = "changed"
	if err := ValidateResourceUpdate("AWS::Lambda::Function", before, after); !errors.Is(err, ErrCreateOnly) {
		t.Fatalf("nested immutable update error = %v", err)
	}
}

func TestResourcePatchReadOnlyAndImmutableBoundaries(t *testing.T) {
	for _, path := range []string{"/Arn", "/MetadataTableConfiguration/S3TablesDestination/TableArn", "/MetadataTableConfiguration", ""} {
		if err := ValidateResourcePatchPath("AWS::S3::Bucket", path); err == nil {
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
	after, err := WritableResourceProperties("AWS::S3::Bucket", before)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, want) {
		t.Fatalf("writable model = %#v", after)
	}
}

func TestNestedStackTemplateAndProviderRootHaveDistinctNameRequirements(t *testing.T) {
	properties := Properties{"TemplateBody": `{"Resources":{"Queue":{"Type":"AWS::SQS::Queue"}}}`}
	if err := validateResourceStructure(TemplateResource{Type: "AWS::CloudFormation::Stack", Properties: properties}); err != nil {
		t.Fatalf("nested stack without a provider-root name: %v", err)
	}
	if err := ValidateResourceProperties("AWS::CloudFormation::Stack", properties); err == nil {
		t.Fatal("Cloud Control root admitted without StackName")
	}
	properties["StackName"] = "root"
	if err := ValidateResourceProperties("AWS::CloudFormation::Stack", properties); err != nil {
		t.Fatalf("named provider root: %v", err)
	}
}
