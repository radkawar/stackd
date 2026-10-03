package stackd_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestCloudFormationLambdaLayerApplication(t *testing.T) {
	lambdaURLDocker(t)
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f, role := newCloudFormationVersionStack(t, backend)
			objects := s3.New(s3.Options{Region: cloudFormationLambdaAliasRegion, BaseEndpoint: aws.String(f.clients.server.URL), UsePathStyle: true,
				Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), HTTPClient: f.clients.server.Client(), RetryMaxAttempts: 1})
			bucket := "cfn-layer-archives"
			_, err := objects.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: &bucket})
			if err != nil {
				t.Fatal(err)
			}
			_, err = objects.PutBucketVersioning(t.Context(), &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}})
			if err != nil {
				t.Fatal(err)
			}
			firstArchive := lambdaZIP(t, map[string]string{"python/shared.py": "MARKER='first'\n"})
			secondArchive := lambdaZIP(t, map[string]string{"python/shared.py": "MARKER='second'\n"})
			firstObject, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: aws.String("layer.zip"), Body: bytes.NewReader(firstArchive)})
			if err != nil {
				t.Fatal(err)
			}
			secondObject, err := objects.PutObject(t.Context(), &s3.PutObjectInput{Bucket: &bucket, Key: aws.String("layer.zip"), Body: bytes.NewReader(secondArchive)})
			if err != nil {
				t.Fatal(err)
			}
			template := func(source, marker string) string {
				return cloudFormationLayerTemplate(t, role, bucket, source, marker)
			}
			created, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("layer-application"), TemplateBody: aws.String(template(aws.ToString(firstObject.VersionId), "first"))})
			if err != nil {
				t.Fatal(err)
			}
			f.stackID = aws.ToString(created.StackId)
			initial := f.wait(t, cfntypes.StackStatusCreateComplete)
			firstVersion := cloudFormationVersionOutput(t, initial)
			firstLayer := cloudFormationLayerOutput(t, initial)
			if !strings.Contains(firstLayer, ":layer:Layer:") {
				t.Fatalf("omitted LayerName must use logical ID: %s", firstLayer)
			}
			cloudFormationLayerArchive(t, f, firstLayer, firstArchive)
			cloudFormationVersionInvoke(t, f, firstVersion, "first")
			f.invoke(t, firstVersion, "first", "provisioned-concurrency")
			f.assertMembers(t, f.stackQuery(t, "AWS::Lambda::LayerVersion"), map[string]string{firstLayer: "AWS::Lambda::LayerVersion"})

			// Unlike function versions, same-name/content layer publication always
			// allocates a new version. Deleting that stack must not touch this one.
			var document map[string]any
			if err := json.Unmarshal([]byte(template(aws.ToString(firstObject.VersionId), "first")), &document); err != nil {
				t.Fatal(err)
			}
			layerOnly, err := json.Marshal(map[string]any{"Resources": map[string]any{"Layer": document["Resources"].(map[string]any)["Layer"]}, "Outputs": map[string]any{"LayerRef": map[string]any{"Value": map[string]string{"Ref": "Layer"}}, "LayerARN": map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Layer", "LayerVersionArn"}}}}})
			if err != nil {
				t.Fatal(err)
			}
			sibling, err := f.cfn().CreateStack(t.Context(), &cloudformation.CreateStackInput{StackName: aws.String("same-layer-content"), TemplateBody: aws.String(string(layerOnly))})
			if err != nil {
				t.Fatal(err)
			}
			siblingStack := cloudFormationWait(t, f.clients, f.source, f.cfn(), aws.ToString(sibling.StackId), cfntypes.StackStatusCreateComplete)
			siblingLayer := cloudFormationLayerOutput(t, siblingStack)
			if siblingLayer == firstLayer {
				t.Fatal("independent layer publication adopted the original")
			}
			_, err = f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: sibling.StackId})
			if err != nil {
				t.Fatal(err)
			}
			cloudFormationWait(t, f.clients, f.source, f.cfn(), aws.ToString(sibling.StackId), cfntypes.StackStatusDeleteComplete)
			cloudFormationLayerArchive(t, f, firstLayer, firstArchive)
			_, err = objects.DeleteObject(t.Context(), &s3.DeleteObjectInput{Bucket: &bucket, Key: aws.String("layer.zip"), VersionId: firstObject.VersionId})
			if err != nil {
				t.Fatal(err)
			}

			f.update(t, template(aws.ToString(secondObject.VersionId), "second"), cfntypes.StackStatusUpdateComplete)
			updated := f.wait(t, cfntypes.StackStatusUpdateComplete)
			secondVersion := cloudFormationVersionOutput(t, updated)
			secondLayer := cloudFormationLayerOutput(t, updated)
			if firstLayer == secondLayer {
				t.Fatal("changed layer content did not replace the publication")
			}
			cloudFormationLayerArchive(t, f, secondLayer, secondArchive)
			_, err = f.native().GetLayerVersionByArn(t.Context(), &awslambda.GetLayerVersionByArnInput{Arn: &firstLayer})
			assertAPIError(t, err, "ResourceNotFoundException")
			f.assertMembers(t, f.stackQuery(t, "AWS::Lambda::LayerVersion"), map[string]string{secondLayer: "AWS::Lambda::LayerVersion"})
			f.clients = f.reopen()
			// The old published function retains its layer attachment even though
			// both the layer catalog version and original S3 source were deleted.
			cloudFormationVersionInvoke(t, f, firstVersion, "first")
			cloudFormationVersionInvoke(t, f, secondVersion, "second")
			f.invoke(t, secondVersion, "second", "provisioned-concurrency")
			current, err := f.native().GetLayerVersionByArn(t.Context(), &awslambda.GetLayerVersionByArnInput{Arn: &secondLayer})
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.native().DeleteLayerVersion(t.Context(), &awslambda.DeleteLayerVersionInput{LayerName: aws.String("Layer"), VersionNumber: aws.Int64(current.Version)})
			if err != nil {
				t.Fatal(err)
			}
			f.assertMembers(t, f.stackQuery(t, "AWS::Lambda::LayerVersion"), map[string]string{})
			f.clients = f.reopen()
			cloudFormationVersionInvoke(t, f, secondVersion, "second")
			_, err = f.cfn().DeleteStack(t.Context(), &cloudformation.DeleteStackInput{StackName: aws.String(f.stackID)})
			if err != nil {
				t.Fatal(err)
			}
			f.wait(t, cfntypes.StackStatusDeleteComplete)
			_, err = f.native().GetFunction(t.Context(), &awslambda.GetFunctionInput{FunctionName: aws.String(cloudFormationLambdaFunctionName)})
			assertAPIError(t, err, "ResourceNotFoundException")
		})
	}
}

func cloudFormationLayerTemplate(t *testing.T, role, bucket, sourceVersion, marker string) string {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(cloudFormationVersionTemplate(t, role, marker)), &document); err != nil {
		t.Fatal(err)
	}
	resources := document["Resources"].(map[string]any)
	resources["Layer"] = map[string]any{"Type": "AWS::Lambda::LayerVersion", "Properties": map[string]any{
		"Content":     map[string]string{"S3Bucket": bucket, "S3Key": "layer.zip", "S3ObjectVersion": sourceVersion, "S3ObjectStorageMode": "COPY"},
		"Description": marker, "LicenseInfo": "MIT", "CompatibleRuntimes": []string{"python3.12"}, "CompatibleArchitectures": []string{"x86_64"},
	}}
	function := resources["Function"].(map[string]any)["Properties"].(map[string]any)
	function["Code"] = map[string]string{"ZipFile": "import os\nfrom shared import MARKER\ndef handler(event,context):\n return {'marker':MARKER,'version':context.function_version,'initialization':os.environ['AWS_LAMBDA_INITIALIZATION_TYPE']}\n"}
	function["Layers"] = []any{map[string]string{"Ref": "Layer"}}
	resources["Version"].(map[string]any)["UpdateReplacePolicy"] = "Retain"
	outputs := document["Outputs"].(map[string]any)
	outputs["LayerRef"] = map[string]any{"Value": map[string]string{"Ref": "Layer"}}
	outputs["LayerARN"] = map[string]any{"Value": map[string]any{"Fn::GetAtt": []string{"Layer", "LayerVersionArn"}}}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func cloudFormationLayerOutput(t *testing.T, stack cfntypes.Stack) string {
	t.Helper()
	values := map[string]string{}
	for _, output := range stack.Outputs {
		values[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
	}
	if values["LayerRef"] != values["LayerARN"] || !strings.HasPrefix(values["LayerRef"], "arn:aws:lambda:"+cloudFormationLambdaAliasRegion+":000000000000:layer:") {
		t.Fatalf("wrong layer Ref/GetAtt: %v", values)
	}
	return values["LayerRef"]
}

func cloudFormationLayerArchive(t *testing.T, f *cloudFormationLambdaAliasStack, arn string, archive []byte) {
	t.Helper()
	out, err := f.native().GetLayerVersionByArn(t.Context(), &awslambda.GetLayerVersionByArnInput{Arn: &arn})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive)
	if out.Content == nil || aws.ToString(out.Content.CodeSha256) != base64.StdEncoding.EncodeToString(digest[:]) || out.Content.CodeSize != int64(len(archive)) {
		t.Fatalf("layer did not pin requested S3 bytes: %+v", out.Content)
	}
}
