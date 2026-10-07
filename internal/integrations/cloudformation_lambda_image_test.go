package integrations

import (
	"testing"

	runtime "stackd/compute/lambda"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
	service "stackd/internal/services/lambda"
)

func TestCFNLambdaImagePackageValidationAndReplacement(t *testing.T) {
	h := cfnLambdaFunction{}
	image := cloudformation.Properties{"Role": "arn:aws:iam::111111111111:role/execution", "PackageType": "Image", "Code": map[string]any{"ImageUri": "local-unified:latest"}, "ImageConfig": map[string]any{"Command": []any{"index.handler"}, "WorkingDirectory": "/var/task"}, "VpcConfig": map[string]any{"SubnetIds": []any{"subnet-a"}, "SecurityGroupIds": []any{"sg-a"}}}
	if err := h.Validate(image); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]any{"Runtime": "python3.12", "Handler": "index.handler", "Layers": []any{"arn:aws:lambda:us-east-1:111111111111:layer:one:1"}} {
		properties := cloudformation.Properties{}
		for k, v := range image {
			properties[k] = v
		}
		properties[key] = value
		if err := h.Validate(properties); err == nil {
			t.Fatalf("Image accepted ZIP-only %s", key)
		}
	}
	mixed := cloudformation.Properties{}
	for k, v := range image {
		mixed[k] = v
	}
	mixed["Code"] = map[string]any{"ImageUri": "local-unified:latest", "S3Bucket": "code", "S3Key": "function.zip"}
	if err := h.Validate(mixed); err == nil {
		t.Fatal("Image accepted mixed code sources")
	}
	zip := cloudformation.Properties{"Role": image["Role"], "Code": map[string]any{"S3Bucket": "code", "S3Key": "function.zip"}, "Runtime": "provided.al2023", "Handler": "bootstrap"}
	if err := h.Validate(zip); err != nil {
		t.Fatal(err)
	}
	if replace, err := h.Replacement(zip, image); err != nil || !replace {
		t.Fatalf("package cutover must replace: %v %v", replace, err)
	}
	next := cloudformation.Properties{}
	for key, value := range image {
		next[key] = value
	}
	next["Code"] = map[string]any{"ImageUri": "local-unified:next"}
	if replace, err := h.Replacement(image, next); err != nil || replace {
		t.Fatalf("image code update must not replace: %v %v", replace, err)
	}
	configuration := cfnLambdaConfiguration(image)
	if _, found := configuration["Layers"]; found {
		t.Fatal("image configuration update includes ZIP Layers")
	}
}

func TestCFNLambdaFunctionLiveImageReadAndPrivateRecreationFence(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNLambdaAdditionalFixture(t, backend)
			r := cfnLambdaAdditionalRequest("AWS::Lambda::Function", cloudformation.Properties{"FunctionName": "configured", "Role": "arn:aws:iam::111111111111:role/execution", "PackageType": "Image", "Code": map[string]any{"ImageUri": "local-image:latest"}})
			r.PhysicalID = "configured"
			key := service.FunctionKey{Scope: service.Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}, Name: r.PhysicalID}
			if err := f.repo.Update(f.ctx, func(tx service.Transaction) error {
				record, err := tx.Function(key)
				if err != nil {
					return err
				}
				record.Runtime, record.Handler = "", ""
				record.Owner = service.FunctionOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token}
				record.Tags = cfnLambdaDeploymentTags(r)
				record.Tags["customer"] = "visible"
				record.Image = &runtime.Image{URI: "local-image:latest", ID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ResolvedURI: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EntryPoint: []string{"/bootstrap"}, Command: []string{"handler"}}
				record.ImageConfig = &api.ImageConfig{Command: api.StringList{"override"}}
				return tx.PutFunction(record)
			}); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			h := cfnLambdaFunction{f.commands}
			if recovered, err := h.Create(f.ctx, r); err != nil || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("private image claim did not recover without public owner tags: %+v %v", recovered, err)
			}
			properties, err := h.Read(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			if properties["PackageType"] != "Image" || properties["Arn"] != key.ARN() || properties["Runtime"] != nil || properties["Handler"] != nil || properties["Code"] != nil {
				t.Fatalf("live image model: %+v", properties)
			}
			tags, err := cfnComputeTags(properties)
			if err != nil || len(tags) != 1 || tags["customer"] != "visible" {
				t.Fatalf("private discovery tags leaked: %+v %v", properties["Tags"], err)
			}
			discovery := r
			discovery.CloudControl = true
			rows, err := h.List(f.ctx, discovery)
			if err != nil || len(rows) != 1 {
				t.Fatalf("live owner list: %+v %v", rows, err)
			}
			identifier, err := cloudformation.ResourceIdentifier(r.Type, rows[0].Properties)
			if err != nil || rows[0].Identifier != identifier {
				t.Fatalf("list did not use the provider identifier: %+v %v", rows[0], err)
			}
			if rows[0].Properties["Arn"] != key.ARN() || rows[0].Properties["PackageType"] != "Image" || rows[0].Properties["Code"] != nil {
				t.Fatalf("list lost the schema image projection: %+v", rows[0])
			}
			if err := f.repo.Update(f.ctx, func(tx service.Transaction) error {
				record, err := tx.Function(key)
				if err != nil {
					return err
				}
				if err := tx.DeleteFunction(key); err != nil {
					return err
				}
				record.Owner = service.FunctionOwner{}
				for key, value := range cfnComputeOwnedTags(r) {
					record.Tags[key] = value
				}
				record.Revision, record.DeploymentRevision = "native-recreation", "native-recreation"
				return tx.PutFunction(record)
			}); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			h.commands = f.commands
			if err := h.Delete(f.ctx, r); !cfnMessagingMissing(err, "AccessDeniedException") {
				t.Fatalf("old CFN token was not fenced from native same-name recreation with copied tags: %v", err)
			}
			if err := f.repo.View(f.ctx, func(reader service.Reader) error {
				record, err := reader.Function(key)
				if err == nil && record.Revision != "native-recreation" {
					t.Fatal("old owner changed native recreation")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
