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
	service "stackd/internal/services/lambda"
)

type cfnLambdaFunction struct{ commands StepFunctionsCommands }

func cfnLambdaFunctionContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return service.WithFunctionOwner(ctx, service.FunctionOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
}

func (h cfnLambdaFunction) Validate(p cloudformation.Properties) error {
	return h.validate(p, true)
}
func (h cfnLambdaFunction) ValidateUpdate(previous, desired cloudformation.Properties) error {
	if err := h.validate(desired, false); err != nil {
		return err
	}
	if _, before := previous["DurableConfig"]; before {
		if _, after := desired["DurableConfig"]; !after {
			return fmt.Errorf("removing DurableConfig is not supported")
		}
	}
	if _, supplied := desired["Code"]; !supplied && cfnLambdaArchitecture(previous) != cfnLambdaArchitecture(desired) {
		return fmt.Errorf("changing Architectures requires Code")
	}
	return nil
}
func cfnLambdaArchitecture(p cloudformation.Properties) string {
	architectures, _ := cfnComputeStringList(p, "Architectures")
	if len(architectures) == 0 {
		return "x86_64"
	}
	return architectures[0]
}
func (h cfnLambdaFunction) validate(p cloudformation.Properties, creating bool) error {
	if err := cfnComputeProperties(p, "FunctionName", "PackageType", "Code", "Runtime", "Handler", "Role", "Description", "Timeout", "MemorySize", "Environment", "Architectures", "EphemeralStorage", "Layers", "ReservedConcurrentExecutions", "Tags", "ImageConfig", "VpcConfig", "DeadLetterConfig", "LoggingConfig", "TracingConfig", "CodeSigningConfigArn", "DurableConfig"); err != nil {
		return err
	}
	required := []string{"Role"}
	if creating {
		required = append(required, "Code")
	}
	if err := cfnComputeRequired(p, required...); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "FunctionName", "Runtime", "Handler", "Role", "Description", "PackageType", "CodeSigningConfigArn"); err != nil {
		return err
	}
	if kind := cfnComputeString(p, "PackageType"); kind != "" && kind != "Zip" && kind != "Image" {
		return fmt.Errorf("PackageType must be Zip or Image")
	}
	if cfnComputeString(p, "PackageType") == "Image" {
		if _, found := p["Runtime"]; found {
			return fmt.Errorf("image functions cannot specify Runtime")
		}
		if _, found := p["Handler"]; found {
			return fmt.Errorf("image functions cannot specify Handler")
		}
		if _, found := p["Layers"]; found {
			return fmt.Errorf("image functions cannot specify Layers")
		}
		if _, found := p["CodeSigningConfigArn"]; found {
			return fmt.Errorf("image functions cannot specify CodeSigningConfigArn")
		}
	} else if err := cfnComputeRequired(p, "Runtime", "Handler"); err != nil {
		return err
	}
	if _, supplied := p["Code"]; supplied {
		if _, _, err := cfnLambdaCodeProperties(p); err != nil {
			return err
		}
	}
	for key, allowed := range map[string][]string{"Environment": {"Variables"}, "EphemeralStorage": {"Size"}, "ImageConfig": {"EntryPoint", "Command", "WorkingDirectory"}, "VpcConfig": {"SubnetIds", "SecurityGroupIds", "Ipv6AllowedForDualStack"}, "DeadLetterConfig": {"TargetArn"}, "LoggingConfig": {"LogGroup", "LogFormat", "ApplicationLogLevel", "SystemLogLevel"}, "TracingConfig": {"Mode"}, "DurableConfig": {"ExecutionTimeout", "RetentionPeriodInDays", "KMSKeyArn"}} {
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
	if image, found := cfnComputeObject(p["ImageConfig"]); found {
		if _, err := cfnComputeStringList(image, "EntryPoint"); err != nil {
			return err
		}
		if _, err := cfnComputeStringList(image, "Command"); err != nil {
			return err
		}
		if err := cfnComputeStrings(image, "WorkingDirectory"); err != nil {
			return err
		}
		if cfnComputeString(p, "PackageType") != "Image" {
			return fmt.Errorf("ImageConfig requires PackageType Image")
		}
	}
	if vpc, found := cfnComputeObject(p["VpcConfig"]); found {
		if _, err := cfnComputeStringList(vpc, "SubnetIds"); err != nil {
			return err
		}
		if _, err := cfnComputeStringList(vpc, "SecurityGroupIds"); err != nil {
			return err
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
	for _, architecture := range architectures {
		if architecture != "x86_64" && architecture != "arm64" {
			return fmt.Errorf("architectures must contain x86_64 or arm64")
		}
	}
	_, err = cfnComputeTags(p)
	return err
}
func cfnLambdaCodeProperties(p map[string]any) (map[string]any, string, error) {
	code, ok := cfnComputeObject(p["Code"])
	if !ok {
		return nil, "", fmt.Errorf("property Code must be an object")
	}
	if err := cfnComputeProperties(code, "ZipFile", "S3Bucket", "S3Key", "S3ObjectVersion", "ImageUri", "S3ObjectStorageMode"); err != nil {
		return nil, "", err
	}
	if err := cfnComputeStrings(code, "ZipFile", "S3Bucket", "S3Key", "S3ObjectVersion", "ImageUri", "S3ObjectStorageMode"); err != nil {
		return nil, "", err
	}
	if cfnComputeString(p, "PackageType") == "Image" {
		if len(code) != 1 || cfnComputeString(code, "ImageUri") == "" {
			return nil, "", fmt.Errorf("image Code requires only ImageUri")
		}
		return code, "", nil
	}
	if _, found := code["ImageUri"]; found {
		return nil, "", fmt.Errorf("Code.ImageUri requires PackageType Image")
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
	source := cfnComputeCopy(code, "S3Bucket", "S3Key", "S3ObjectVersion", "ImageUri", "S3ObjectStorageMode")
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
	if err := awsapi.DecodeCloudFormationInput(model.Service, model.Operation, body, typed); err != nil {
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
		configuration, _ := out.Output.(*api.FunctionConfiguration)
		return configuration, rejected
	}
	configuration, ok := out.Output.(*api.FunctionConfiguration)
	if !ok {
		return nil, fmt.Errorf("lambda %s returned unexpected output %T", operation, out.Output)
	}
	return configuration, nil
}
func (h cfnLambdaFunction) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.ValidateUpdate(a, b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "FunctionName") || cfnComputeDefault(a, "PackageType", "Zip") != cfnComputeDefault(b, "PackageType", "Zip"), nil
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
	desired, err := cfnComputeTags(r.Properties)
	if err != nil {
		return err
	}
	// Direct requests preserve deployment phase metadata, not a public tag claim.
	for key, value := range current {
		if strings.HasPrefix(key, cfnComputeTagPrefix) {
			desired[key] = value
		}
	}
	if !r.CloudControl {
		for key, value := range r.Tags {
			if _, supplied := desired[key]; !supplied {
				desired[key] = value
			}
		}
	}
	for key, value := range cfnLambdaPhaseTags(r) {
		if key != cfnComputeTagPrefix+"last-admission" {
			desired[key] = value
		}
	}
	if removed := cfnComputeRemovedTags(current, desired); len(removed) > 0 {
		if err := cfnComputeRun(ctx, c, "lambda", "UntagResource", map[string]any{"Resource": arn, "TagKeys": removed}); err != nil {
			return err
		}
	}
	return cfnComputeRun(ctx, c, "lambda", "TagResource", map[string]any{"Resource": arn, "Tags": desired})
}
func (h cfnLambdaFunction) owned(ctx context.Context, r cloudformation.ResourceRequest, name string) (*api.FunctionConfiguration, map[string]string, error) {
	ctx = cfnLambdaFunctionContext(ctx, r, false)
	out, err := cfnComputeCall[api.GetFunctionConfigurationOutput](ctx, h.commands, "lambda", "GetFunctionConfiguration", map[string]any{"FunctionName": name})
	if err != nil {
		return nil, nil, err
	}
	tags, err := cfnLambdaTags(ctx, h.commands, cfnComputeValue(out.FunctionArn))
	if err != nil {
		return out, nil, err
	}
	return out, tags, nil
}
func cfnLambdaResult(function *api.FunctionConfiguration) cloudformation.ResourceResult {
	name := cfnComputeValue(function.FunctionName)
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": cfnComputeValue(function.FunctionArn)}}
}
func cfnLambdaConfiguration(p cloudformation.Properties) map[string]any {
	input := cfnComputeCopy(p, "Runtime", "Handler", "Role", "DeadLetterConfig", "LoggingConfig", "TracingConfig", "DurableConfig")
	for key, fallback := range map[string]any{"Description": "", "Timeout": 3, "MemorySize": 128, "Environment": map[string]any{"Variables": map[string]string{}}, "EphemeralStorage": map[string]any{"Size": 512}, "Layers": []string{}} {
		input[key] = cfnComputeDefault(p, key, fallback)
	}
	input["VpcConfig"] = cfnComputeDefault(p, "VpcConfig", map[string]any{"SubnetIds": []string{}, "SecurityGroupIds": []string{}})
	input["DeadLetterConfig"] = cfnComputeDefault(p, "DeadLetterConfig", map[string]any{})
	input["LoggingConfig"] = cfnComputeDefault(p, "LoggingConfig", map[string]any{})
	input["TracingConfig"] = cfnComputeDefault(p, "TracingConfig", map[string]any{"Mode": "PassThrough"})
	if cfnComputeString(p, "PackageType") == "Image" {
		delete(input, "Layers")
		input["ImageConfig"] = cfnComputeDefault(p, "ImageConfig", map[string]any{})
	}
	return input
}
func cfnLambdaPhaseTags(r cloudformation.ResourceRequest) map[string]string {
	if r.Type == "AWS::Lambda::EventSourceMapping" {
		body, _ := json.Marshal(cfnLambdaMappingCreateInput(r.Properties))
		return map[string]string{cfnComputeTagPrefix + "mapping": cfnComputeHash(string(body))}
	}
	configuration, _ := json.Marshal(cfnLambdaConfiguration(r.Properties))
	if _, supplied := r.Properties["Code"]; !supplied {
		return map[string]string{cfnComputeTagPrefix + "configuration": cfnComputeHash(string(configuration))}
	}
	code, _ := json.Marshal(cfnComputeCopy(r.Properties, "Code", "Architectures", "Runtime", "PackageType"))
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
	tags := make(map[string]string, len(r.Tags)+3)
	for key, value := range r.Tags {
		tags[key] = value
	}
	public, _ := cfnComputeTags(r.Properties)
	for key, value := range public {
		tags[key] = value
	}
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

// RecoverCreation reads only the native incarnation carrying this private
// claim. It never retries deployment or revalidates rejected create properties.
func (h cfnLambdaFunction) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = service.WithFunctionCreationRecovery(ctx, service.FunctionOwner{StackID: r.StackID, LogicalID: r.LogicalID, Token: r.Token})
	name := r.PhysicalID
	if name == "" {
		name = cfnComputeName(r, "FunctionName", 64)
	}
	// Rejected public names must not be revalidated before the trusted native
	// owner observes the private token; ordinary public reads keep their codec.
	observed, rejected := h.commands.CallTyped(ctx, "lambda", "GetFunctionConfiguration", &api.GetFunctionConfigurationInput{FunctionName: new(api.NamespacedFunctionName(name))})
	if rejected != nil {
		return cloudformation.ResourceResult{}, rejected
	}
	function, ok := observed.Output.(*api.GetFunctionConfigurationOutput)
	if !ok {
		return cloudformation.ResourceResult{}, fmt.Errorf("lambda.GetFunctionConfiguration returned unexpected output %T", observed.Output)
	}
	return cfnLambdaResult(function), nil
}

func (h cfnLambdaFunction) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnLambdaFunctionContext(ctx, r, true)
	// Recovery first: validation/convergence can reject a replay after the
	// exact native incarnation has already been admitted.
	name := cfnComputeName(r, "FunctionName", 64)
	ownedRequest := r
	ownedRequest.CloudControl = false
	function, _, err := h.owned(ctx, ownedRequest, name)
	if err != nil && !cfnComputeMissing(err) {
		if function != nil {
			return cfnLambdaResult(function), err
		}
		return cloudformation.ResourceResult{}, err
	}
	if validation := h.Validate(r.Properties); validation != nil {
		if function != nil {
			return cfnLambdaResult(function), validation
		}
		return cloudformation.ResourceResult{}, validation
	}
	if cfnComputeMissing(err) {
		input := cfnComputeCopy(r.Properties, "PackageType", "Runtime", "Handler", "Role", "Description", "Timeout", "MemorySize", "Environment", "Architectures", "EphemeralStorage", "Layers", "ImageConfig", "VpcConfig", "DeadLetterConfig", "LoggingConfig", "TracingConfig", "CodeSigningConfigArn", "DurableConfig")
		input["FunctionName"] = name
		input["Tags"] = cfnLambdaDeploymentTags(r)
		function, err = h.deploy(ctx, "CreateFunction", r.Properties, input)
		if err != nil {
			if function != nil {
				return cfnLambdaResult(function), err
			}
			if admitted, _, _ := h.owned(ctx, ownedRequest, name); admitted != nil {
				return cfnLambdaResult(admitted), err
			}
			return cloudformation.ResourceResult{}, err
		}
	}
	return cfnLambdaResult(function), nil
}
func (h cfnLambdaFunction) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ctx = cfnLambdaFunctionContext(ctx, r, false)
	if err := h.validate(r.Properties, false); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	function, _, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnLambdaLiveTransition(function, r.Properties); err != nil {
		return cfnLambdaResult(function), err
	}
	return cfnLambdaResult(function), nil
}

func cfnLambdaLiveTransition(function *api.FunctionConfiguration, desired cloudformation.Properties) error {
	_, enabled := desired["DurableConfig"]
	if function.DurableConfig != nil && !enabled {
		return fmt.Errorf("removing DurableConfig is not supported")
	}
	if function.DurableConfig == nil && enabled {
		return fmt.Errorf("DurableConfig must be enabled when the function is created")
	}
	if _, supplied := desired["Code"]; !supplied {
		architecture := "x86_64"
		if len(function.Architectures) > 0 {
			architecture = string(function.Architectures[0])
		}
		if architecture != cfnLambdaArchitecture(desired) {
			return fmt.Errorf("changing Architectures requires Code")
		}
	}
	return nil
}

// Stabilize admits one phase at a time and yields to the shared job driver.
// Phase hashes are written only after owner admission; a crash before that
// write repeats the same update after the in-progress deployment completes.
func (h cfnLambdaFunction) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	ctx = cfnLambdaFunctionContext(ctx, r, false)
	function, current, err := h.owned(ctx, r, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if err := h.validate(r.Properties, false); err != nil {
		return false, err
	}
	if err := cfnLambdaLiveTransition(function, r.Properties); err != nil {
		return false, err
	}
	state, status := cfnComputeValue(function.State), cfnComputeValue(function.LastUpdateStatus)
	desired := cfnLambdaPhaseTags(r)
	if state == "Failed" || status == "Failed" {
		phase, hash, found := strings.Cut(current[cfnComputeTagPrefix+"last-admission"], ":")
		// A failed desired deployment is terminal. A distinct rollback intent may
		// restore the previous configuration/code through the normal owner command.
		if !found || desired[cfnComputeTagPrefix+phase] == hash || desired[cfnComputeTagPrefix+phase] == "" {
			return false, fmt.Errorf("lambda deployment failed: %s %s", cfnComputeValue(function.StateReason), cfnComputeValue(function.LastUpdateStatusReason))
		}
	}
	if state == "Pending" || status == "InProgress" {
		return false, nil
	}
	arn := cfnComputeValue(function.FunctionArn)
	if _, supplied := r.Properties["CodeSigningConfigArn"]; supplied || r.Previous["CodeSigningConfigArn"] != nil {
		currentSigning, err := cfnComputeCall[api.GetFunctionCodeSigningConfigOutput](ctx, h.commands, "lambda", "GetFunctionCodeSigningConfig", map[string]any{"FunctionName": r.PhysicalID})
		if err != nil {
			return false, err
		}
		desiredSigning := cfnComputeString(r.Properties, "CodeSigningConfigArn")
		if cfnComputeValue(currentSigning.CodeSigningConfigArn) != desiredSigning {
			if desiredSigning == "" {
				err = cfnComputeRun(ctx, h.commands, "lambda", "DeleteFunctionCodeSigningConfig", map[string]any{"FunctionName": r.PhysicalID})
			} else {
				err = cfnComputeRun(ctx, h.commands, "lambda", "PutFunctionCodeSigningConfig", map[string]any{"FunctionName": r.PhysicalID, "CodeSigningConfigArn": desiredSigning})
			}
			return false, err
		}
	}
	for _, phase := range []string{"configuration", "code"} {
		key := cfnComputeTagPrefix + phase
		if _, supplied := desired[key]; !supplied {
			continue
		}
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
	ctx = cfnLambdaFunctionContext(ctx, r, false)
	name := r.PhysicalID
	if name == "" {
		name = cfnComputeName(r, "FunctionName", 64)
	}
	if _, _, err := h.owned(ctx, r, name); err != nil {
		return cfnComputeAbsent(err)
	}
	return cfnComputeAbsent(cfnComputeRun(ctx, h.commands, "lambda", "DeleteFunction", map[string]any{"FunctionName": name}))
}
