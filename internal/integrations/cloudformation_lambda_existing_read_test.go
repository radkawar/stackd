package integrations

import (
	"archive/zip"
	"bytes"
	"testing"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/lambda"
)

func TestCFNLambdaQualifiedAuthoritativeReaders(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			published, err := cfnMessagingCall[api.PublishVersionOutput](f.ctx, f.commands, "lambda", "PublishVersion", &api.PublishVersionInput{FunctionName: new(api.FunctionName("configured")), Description: new(api.Description("published metadata"))})
			if err != nil {
				t.Fatal(err)
			}
			version := cfnLambdaVersion{f.commands}
			r := cfnLambdaAdditionalRequest("AWS::Lambda::Version", nil)
			r.CloudControl = true
			r.PhysicalID = cfnComputeValue(published.FunctionArn)
			properties, err := version.Read(f.ctx, r)
			if err != nil || properties["Version"] != "1" || properties["Description"] != "published metadata" || properties["FunctionName"] != "arn:aws:lambda:us-east-1:111111111111:function:configured" {
				t.Fatalf("version projection: %+v %v", properties, err)
			}
			rows, err := version.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true, Properties: cloudformation.Properties{"FunctionName": "configured"}})
			if err != nil || len(rows) != 1 || rows[0].Identifier != r.PhysicalID {
				t.Fatalf("version list: %+v %v", rows, err)
			}
			alias := cfnLambdaAlias{f.commands}
			a := cfnLambdaAdditionalRequest("AWS::Lambda::Alias", cloudformation.Properties{"FunctionName": "configured", "Name": "production", "FunctionVersion": "1", "Description": "live alias"})
			result, err := alias.Create(f.ctx, a)
			if err != nil {
				t.Fatal(err)
			}
			a.PhysicalID = result.PhysicalID
			f.reopen(t)
			version.commands, alias.commands = f.commands, f.commands
			properties, err = alias.Read(f.ctx, a)
			if err != nil || properties["Name"] != "production" || properties["FunctionVersion"] != "1" || properties["Description"] != "live alias" {
				t.Fatalf("alias read after recovery: %+v %v", properties, err)
			}
			rows, err = alias.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true, Properties: cloudformation.Properties{"FunctionName": "configured"}})
			if err != nil || len(rows) != 1 || rows[0].Identifier != a.PhysicalID {
				t.Fatalf("alias list: %+v %v", rows, err)
			}
			f.authority.denied = "lambda:GetAlias"
			if _, err := alias.Read(f.ctx, a); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("alias read bypassed current authority: %v", err)
			}
			f.authority.denied = "lambda:GetFunctionConfiguration"
			if _, err := version.Read(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("version read bypassed current authority: %v", err)
			}
		})
	}
}

func TestCFNLambdaPermissionCompoundReadDelete(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			h := cfnLambdaPermission{f.commands}
			r := cfnLambdaAdditionalRequest("AWS::Lambda::Permission", cloudformation.Properties{"FunctionName": "configured", "Action": "lambda:InvokeFunction", "Principal": "sns.amazonaws.com", "SourceArn": "arn:aws:sns:us-east-1:111111111111:events", "SourceAccount": "111111111111", "InvokedViaFunctionUrl": true})
			r.CloudControl = true
			result, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = result.PhysicalID
			r.Properties = nil
			f.reopen(t)
			h.commands = f.commands
			properties, err := h.Read(f.ctx, r)
			if err != nil || properties["Id"] != result.Attributes["Id"] || properties["Principal"] != "sns.amazonaws.com" || properties["InvokedViaFunctionUrl"] != true || properties["SourceAccount"] != "111111111111" {
				t.Fatalf("permission read: %+v %v", properties, err)
			}
			rows, err := h.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true, Properties: cloudformation.Properties{"FunctionName": "configured"}})
			if err != nil || len(rows) != 1 || rows[0].Identifier != result.PhysicalID {
				t.Fatalf("permission compound list: %+v %v", rows, err)
			}
			f.authority.denied = "lambda:GetPolicy"
			if _, err := h.Read(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("permission read bypassed current IAM: %v", err)
			}
			f.authority.denied = ""
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Read(f.ctx, r); !cfnComputeMissing(err) {
				t.Fatalf("permission remains readable after delete: %v", err)
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCFNLambdaLayerAuthoritativeReaders(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			member, err := writer.Create("python/helper.py")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := member.Write([]byte("def helper(): return 1\n")); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			published, err := cfnMessagingCall[api.PublishLayerVersionOutput](f.ctx, f.commands, "lambda", "PublishLayerVersion", &api.PublishLayerVersionInput{LayerName: new(api.LayerName("shared")), Description: new(api.Description("layer metadata")), LicenseInfo: new(api.LicenseInfo("MIT")), Content: &api.LayerVersionContentInput{ZipFile: archive.Bytes()}, CompatibleRuntimes: api.CompatibleRuntimes{api.Runtime("python3.12")}})
			if err != nil {
				t.Fatal(err)
			}
			layer := cfnLambdaLayerVersion{f.commands}
			r := cloudformation.ResourceRequest{CloudControl: true, PhysicalID: cfnComputeValue(published.LayerVersionArn)}
			properties, err := layer.Read(f.ctx, r)
			if err != nil || properties["LayerVersionArn"] != r.PhysicalID || properties["Description"] != "layer metadata" {
				t.Fatalf("layer read: %+v %v", properties, err)
			}
			if _, present := properties["Content"]; present {
				t.Fatal("layer read leaked fabricated write-only Content")
			}
			permission := cfnLambdaLayerPermission{f.commands}
			p := cfnLambdaAdditionalRequest("AWS::Lambda::LayerVersionPermission", cloudformation.Properties{"LayerVersionArn": r.PhysicalID, "Principal": "*", "Action": "lambda:GetLayerVersion", "OrganizationId": "o-abcdefghij"})
			result, err := permission.Create(f.ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			p.PhysicalID = result.PhysicalID
			f.reopen(t)
			layer.commands, permission.commands = f.commands, f.commands
			properties, err = permission.Read(f.ctx, p)
			if err != nil || properties["Id"] != p.PhysicalID || properties["OrganizationId"] != "o-abcdefghij" {
				t.Fatalf("layer permission read after recovery: %+v %v", properties, err)
			}
			rows, err := permission.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true, Properties: cloudformation.Properties{"LayerVersionArn": r.PhysicalID}})
			if err != nil || len(rows) != 1 || rows[0].Identifier != p.PhysicalID {
				t.Fatalf("layer permission list: %+v %v", rows, err)
			}
			rows, err = layer.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true, Properties: cloudformation.Properties{"LayerName": "shared"}})
			if err != nil || len(rows) != 1 {
				t.Fatalf("layer list: %+v %v", rows, err)
			}
			f.authority.denied = "lambda:GetLayerVersion"
			if _, err := layer.Read(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("layer read bypassed current IAM: %v", err)
			}
			f.authority.denied = "lambda:GetLayerVersionPolicy"
			if _, err := permission.Read(f.ctx, p); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("layer permission read bypassed current IAM: %v", err)
			}
		})
	}
}

func TestCFNLambdaMappingRetainedRead(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			key := lambda.FunctionKey{Scope: lambda.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: "configured"}
			mapping := lambda.EventSourceMappingRecord{Key: lambda.EventSourceMappingKey{Scope: key.Scope, UUID: "12345678-1234-1234-1234-123456789012"}, Function: lambda.FunctionReference{FunctionKey: key}, EventSourceARN: "arn:aws:sqs:us-east-1:111111111111:events", State: "Disabled", Settings: lambda.EventSourceMappingSettings{BatchSize: 10}, Tags: map[string]string{"application": "orders"}, LastModified: f.manual.Now()}
			// A retained, disabled mapping is read from its real owner. No SQS
			// execution adapter is fabricated to pretend a create effect succeeded.
			if err := f.repo.Update(f.ctx, func(tx lambda.Transaction) error { return tx.PutEventSourceMapping(mapping) }); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			h := cfnLambdaMapping{f.commands}
			r := cloudformation.ResourceRequest{CloudControl: true, PhysicalID: mapping.Key.UUID}
			properties, err := h.Read(f.ctx, r)
			if err != nil || properties["Id"] != mapping.Key.UUID || properties["Enabled"] != false || properties["FunctionName"] != key.ARN() || properties["EventSourceMappingArn"] != mapping.Key.ARN() {
				t.Fatalf("retained mapping projection: %+v %v", properties, err)
			}
			rows, err := h.List(f.ctx, cloudformation.ResourceRequest{CloudControl: true})
			if err != nil || len(rows) != 1 || rows[0].Identifier != mapping.Key.UUID {
				t.Fatalf("mapping live list: %+v %v", rows, err)
			}
			f.authority.denied = "lambda:GetEventSourceMapping"
			if _, err := h.Read(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("mapping read bypassed current IAM: %v", err)
			}
		})
	}
}

func TestCFNLambdaNativeListFilterRequirements(t *testing.T) {
	readers := []cloudformation.ResourceReader{cfnLambdaAlias{}, cfnLambdaVersion{}, cfnLambdaLayerVersion{}, cfnLambdaLayerPermission{}, cfnLambdaPermission{}, cfnLambdaEventInvokeConfig{}, cfnLambdaURL{}}
	for _, reader := range readers {
		if _, err := reader.List(t.Context(), cloudformation.ResourceRequest{CloudControl: true}); !cfnMessagingMissing(err, "InvalidParameterValueException") {
			t.Fatalf("%T invented an unfiltered native list: %v", reader, err)
		}
	}
	statement := map[string]any{"Sid": "deny", "Effect": "Deny", "Principal": "*", "Resource": "arn:aws:lambda:us-east-1:111111111111:function:configured", "Action": "lambda:InvokeFunction"}
	if _, supported := cfnLambdaPermissionModel(statement, false); supported {
		t.Fatal("arbitrary deny policy was flattened into a native permission resource")
	}
	if _, err := cfnLambdaPermissionReadModel([]map[string]any{statement}, "deny", false); !cfnMessagingMissing(err, "UnsupportedActionException") {
		t.Fatalf("unrepresentable statement read: %v", err)
	}
}
