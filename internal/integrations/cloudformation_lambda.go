package integrations

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

type cfnLambdaFunction struct{ commands StepFunctionsCommands }

func (h cfnLambdaFunction) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "FunctionName", "PackageType", "Code", "Runtime", "Handler", "Role", "Description", "Timeout", "MemorySize", "Environment", "Architectures", "EphemeralStorage", "Layers", "ReservedConcurrentExecutions", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "Code", "Runtime", "Handler", "Role"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "FunctionName", "Runtime", "Handler", "Role", "Description"); err != nil {
		return err
	}
	if value, found := p["PackageType"]; found && value != "Zip" {
		return fmt.Errorf("only Zip Lambda packages are supported")
	}
	if _, _, err := cfnLambdaCodeProperties(p); err != nil {
		return err
	}
	for key, allowed := range map[string][]string{"Environment": {"Variables"}, "EphemeralStorage": {"Size"}} {
		if value, found := p[key]; found {
			object, ok := cfnComputeObject(value)
			if !ok {
				return fmt.Errorf("%s must be an object", key)
			}
			if err := cfnComputeProperties(object, allowed...); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	if _, err := cfnComputeStringList(p, "Layers"); err != nil {
		return err
	}
	architectures, err := cfnComputeStringList(p, "Architectures")
	if err != nil {
		return err
	}
	if len(architectures) > 1 {
		return fmt.Errorf("exactly one architecture is supported")
	}
	_, err = cfnComputeTags(p)
	return err
}
func cfnLambdaCodeProperties(p map[string]any) (map[string]any, string, error) {
	code, ok := cfnComputeObject(p["Code"])
	if !ok {
		return nil, "", fmt.Errorf("property Code must be an object")
	}
	if err := cfnComputeProperties(code, "ZipFile", "S3Bucket", "S3Key", "S3ObjectVersion"); err != nil {
		return nil, "", err
	}
	if err := cfnComputeStrings(code, "ZipFile", "S3Bucket", "S3Key", "S3ObjectVersion"); err != nil {
		return nil, "", err
	}
	if _, inline := code["ZipFile"]; !inline {
		if cfnComputeString(code, "S3Bucket") == "" || cfnComputeString(code, "S3Key") == "" {
			return nil, "", fmt.Errorf("property Code requires ZipFile or S3Bucket and S3Key")
		}
		return code, "", nil
	}
	if len(code) != 1 {
		return nil, "", fmt.Errorf("Code.ZipFile cannot be combined with S3 code properties")
	}
	runtime := cfnComputeString(p, "Runtime")
	filename := ""
	switch {
	case strings.HasPrefix(runtime, "python"):
		filename = "index.py"
	case strings.HasPrefix(runtime, "nodejs"):
		filename = "index.js"
	default:
		return nil, "", fmt.Errorf("Code.ZipFile supports only Python and Node.js runtimes")
	}
	if !strings.HasPrefix(cfnComputeString(p, "Handler"), "index.") {
		return nil, "", fmt.Errorf("Code.ZipFile Handler must use the index module")
	}
	if len(cfnComputeString(code, "ZipFile")) > 4*1024*1024 {
		return nil, "", fmt.Errorf("inline Code.ZipFile exceeds 4 MiB")
	}
	return code, filename, nil
}

// Inline source is a real deployment ZIP; only the Lambda runtime executes it.
// CallTyped preserves binary bytes: the SDK-task string codec is deliberately
// inappropriate for a binary ZIP (it interprets non-streaming blobs as UTF-8).
func (h cfnLambdaFunction) deploy(ctx context.Context, operation string, p cloudformation.Properties, input map[string]any) (*api.FunctionConfiguration, error) {
	code, filename, err := cfnLambdaCodeProperties(p)
	if err != nil {
		return nil, err
	}
	source := cfnComputeCopy(code, "S3Bucket", "S3Key", "S3ObjectVersion")
	var archiveBytes []byte
	if filename != "" {
		var buffer bytes.Buffer
		archive := zip.NewWriter(&buffer)
		file, err := archive.Create(filename)
		if err != nil {
			return nil, err
		}
		if _, err := file.Write([]byte(cfnComputeString(code, "ZipFile"))); err != nil {
			return nil, err
		}
		if err := archive.Close(); err != nil {
			return nil, err
		}
		if buffer.Len() > 4*1024*1024 {
			return nil, fmt.Errorf("inline deployment ZIP exceeds 4 MiB")
		}
		archiveBytes = buffer.Bytes()
	}
	var typed any
	if operation == "CreateFunction" {
		input["Code"] = source
		typed = &api.CreateFunctionInput{}
	} else {
		for key, value := range source {
			input[key] = value
		}
		typed = &api.UpdateFunctionCodeInput{}
	}
	_, model, rejected := h.commands.resolve("lambda", operation)
	if rejected != nil {
		return nil, rejected
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if err := awsapi.DecodeSDKInput(model.Service, model.Operation, body, typed); err != nil {
		return nil, err
	}
	switch request := typed.(type) {
	case *api.CreateFunctionInput:
		request.Code.ZipFile = archiveBytes
	case *api.UpdateFunctionCodeInput:
		request.ZipFile = archiveBytes
	}
	out, rejected := h.commands.CallTyped(ctx, "lambda", operation, typed)
	if rejected != nil {
		return nil, rejected
	}
	configuration, ok := out.Output.(*api.FunctionConfiguration)
	if !ok {
		return nil, fmt.Errorf("lambda %s returned unexpected output %T", operation, out.Output)
	}
	return configuration, nil
}
func (h cfnLambdaFunction) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "FunctionName"), nil
}
func cfnLambdaTags(ctx context.Context, c StepFunctionsCommands, arn string) (map[string]string, error) {
	out, err := cfnComputeCall[api.ListTagsOutput](ctx, c, "lambda", "ListTags", map[string]any{"Resource": arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for key, value := range out.Tags {
		tags[string(key)] = string(value)
	}
	return tags, nil
}
func cfnLambdaSyncTags(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest, arn string) error {
	current, err := cfnLambdaTags(ctx, c, arn)
	if err != nil {
		return err
	}
	if err := cfnComputeOwnership(r, current); err != nil {
		return err
	}
	desired := cfnComputeOwnedTags(r)
	for key, value := range cfnLambdaPhaseTags(r) {
		desired[key] = value
	}
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "lambda", "UntagResource", map[string]any{"Resource": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	return cfnComputeRun(ctx, c, "lambda", "TagResource", map[string]any{"Resource": arn, "Tags": desired})
}
func (h cfnLambdaFunction) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (*api.FunctionConfiguration, map[string]string, error) {
	out, err := cfnComputeCall[api.GetFunctionConfigurationOutput](ctx, h.commands, "lambda", "GetFunctionConfiguration", map[string]any{"FunctionName": name})
	if err != nil {
		return nil, nil, err
	}
	tags, err := cfnLambdaTags(ctx, h.commands, cfnComputeValue(out.FunctionArn))
	if err != nil {
		return nil, nil, err
	}
	if err := cfnComputeOwnership(r, tags); err != nil {
		return nil, nil, err
	}
	return out, tags, nil
}
func cfnLambdaResult(function *api.FunctionConfiguration) cloudformation.ResourceResult {
	name := cfnComputeValue(function.FunctionName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": cfnComputeValue(function.FunctionArn)}}
}
func cfnLambdaConfiguration(p cloudformation.Properties) map[string]any {
	input := cfnComputeCopy(p, "Runtime", "Handler", "Role")
	for key, fallback := range map[string]any{"Description": "", "Timeout": 3, "MemorySize": 128, "Environment": map[string]any{"Variables": map[string]string{}}, "EphemeralStorage": map[string]any{"Size": 512}, "Layers": []string{}} {
		input[key] = cfnComputeDefault(p, key, fallback)
	}
	return input
}
func cfnLambdaPhaseTags(r cloudformation.ResourceRequest) map[string]string {
	if r.Type == "AWS::Lambda::EventSourceMapping" {
		body, _ := json.Marshal(cfnLambdaMappingCreateInput(r.Properties))
		return map[string]string{cfnComputeTagPrefix + "mapping": cfnComputeHash(string(body))}
	}
	configuration, _ := json.Marshal(cfnLambdaConfiguration(r.Properties))
	code, _ := json.Marshal(cfnComputeCopy(r.Properties, "Code", "Architectures", "Runtime"))
	codeHash := cfnComputeHash(string(code))
	// Reserve every lifecycle tag at creation so later phase admission cannot
	// exceed the owner's tag quota after a deployment was already accepted.
	return map[string]string{
		cfnComputeTagPrefix + "configuration":  cfnComputeHash(string(configuration)),
		cfnComputeTagPrefix + "code":           codeHash,
		cfnComputeTagPrefix + "last-admission": "code:" + codeHash,
	}
}
func cfnLambdaDeploymentTags(r cloudformation.ResourceRequest) map[string]string {
	tags := cfnComputeOwnedTags(r)
	for key, value := range cfnLambdaPhaseTags(r) {
		tags[key] = value
	}
	return tags
}
func (h cfnLambdaFunction) concurrency(ctx context.Context, r cloudformation.ResourceRequest, name string) error {
	if value, found := r.Properties["ReservedConcurrentExecutions"]; found {
		return cfnComputeRun(ctx, h.commands, "lambda", "PutFunctionConcurrency", map[string]any{"FunctionName": name, "ReservedConcurrentExecutions": value})
	}
	if _, found := r.Previous["ReservedConcurrentExecutions"]; found {
		return cfnComputeRun(ctx, h.commands, "lambda", "DeleteFunctionConcurrency", map[string]any{"FunctionName": name})
	}
	return nil
}
func (h cfnLambdaFunction) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeName(r, "FunctionName", 64)
	function, _, err := h.owned(ctx, r, name)
	if err != nil && !cfnComputeMissing(err) {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeMissing(err) {
		input := cfnComputeCopy(r.Properties, "Runtime", "Handler", "Role", "Description", "Timeout", "MemorySize", "Environment", "Architectures", "EphemeralStorage", "Layers")
		input["FunctionName"] = name
		input["Tags"] = cfnLambdaDeploymentTags(r)
		function, err = h.deploy(ctx, "CreateFunction", r.Properties, input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
	}
	return cfnLambdaResult(function), nil
}
func (h cfnLambdaFunction) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	function, _, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLambdaResult(function), nil
}

// Stabilize admits one phase at a time and yields to the shared job driver.
// Phase hashes are written only after owner admission; a crash before that
// write repeats the same update after the in-progress deployment completes.
func (h cfnLambdaFunction) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	function, current, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return false, err
	}
	state, status := cfnComputeValue(function.State), cfnComputeValue(function.LastUpdateStatus)
	desired := cfnLambdaPhaseTags(r)
	if state == "Failed" || status == "Failed" {
		phase, hash, found := strings.Cut(current[cfnComputeTagPrefix+"last-admission"], ":")
		// A failed desired deployment is terminal. A distinct rollback intent may
		// restore the previous configuration/code through the normal owner command.
		if !found || desired[cfnComputeTagPrefix+phase] == hash {
			return false, fmt.Errorf("lambda deployment failed: %s %s", cfnComputeValue(function.StateReason), cfnComputeValue(function.LastUpdateStatusReason))
		}
	}
	if state == "Pending" || status == "InProgress" {
		return false, nil
	}
	arn := cfnComputeValue(function.FunctionArn)
	for _, phase := range []string{"configuration", "code"} {
		key := cfnComputeTagPrefix + phase
		if current[key] == desired[key] {
			continue
		}
		if phase == "configuration" {
			input := cfnLambdaConfiguration(r.Properties)
			input["FunctionName"] = r.PhysicalID
			err = cfnComputeRun(ctx, h.commands, "lambda", "UpdateFunctionConfiguration", input)
		} else {
			input := map[string]any{"FunctionName": r.PhysicalID, "Architectures": cfnComputeDefault(r.Properties, "Architectures", []string{"x86_64"})}
			_, err = h.deploy(ctx, "UpdateFunctionCode", r.Properties, input)
		}
		if err != nil {
			return false, err
		}
		return false, cfnComputeRun(ctx, h.commands, "lambda", "TagResource", map[string]any{"Resource": arn, "Tags": map[string]string{key: desired[key], cfnComputeTagPrefix + "last-admission": phase + ":" + desired[key]}})
	}
	if err := h.concurrency(ctx, r, r.PhysicalID); err != nil {
		return false, err
	}
	if err := cfnLambdaSyncTags(ctx, h.commands, r, arn); err != nil {
		return false, err
	}
	return true, nil
}
func (h cfnLambdaFunction) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnComputeName(r, "FunctionName", 64)
	if _, _, err := h.owned(ctx, r, name); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "lambda", "DeleteFunction", map[string]any{"FunctionName": name}))
}
