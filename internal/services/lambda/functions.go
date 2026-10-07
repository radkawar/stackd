package lambda

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

var environmentName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]+$`)

func tagConditions(tags, requested map[string]string) map[string][]string {
	conditions := map[string][]string{}
	for k, v := range tags {
		conditions["aws:ResourceTag/"+k] = []string{v}
	}
	keys := make([]string, 0, len(requested))
	for k, v := range requested {
		conditions["aws:RequestTag/"+k] = []string{v}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if len(keys) > 0 {
		conditions["aws:TagKeys"] = keys
	}
	return conditions
}
func (s *Service) authorize(ctx context.Context, action, arn string, tags, requested map[string]string, extra map[string][]string) *awswire.Error {
	owner := awsctx.FromContext(ctx).AccountID
	if parts := strings.SplitN(arn, ":", 6); len(parts) == 6 {
		owner = parts[4]
	}
	conditions := tagConditions(tags, requested)
	for key, values := range extra {
		conditions[key] = values
	}
	if wire := s.authorizer.Authorize(ctx, authorization.Request{Action: "lambda:" + action, ResourceARN: arn, ResourceAccountID: owner, Context: conditions}); wire != nil {
		return wireError(wire)
	}
	return nil
}
func configuration(v FunctionRecord) *api.FunctionConfiguration {
	out := &api.FunctionConfiguration{FunctionName: new(api.NamespacedFunctionName(v.Key.Name)), FunctionArn: new(api.NameSpacedFunctionArn((FunctionVersionKey{FunctionKey: v.Key, Version: v.Version}).ARN())), Runtime: new(api.Runtime(v.Runtime)), Role: new(api.RoleArn(v.Role)), Handler: new(api.Handler(v.Handler)), CodeSize: new(api.Long(v.CodeSize)), CodeSha256: new(api.String(v.CodeSHA256)), Description: new(api.Description(v.Description)), Timeout: new(api.Timeout(v.Timeout)), MemorySize: new(api.MemorySize(v.MemoryMB)), LastModified: new(api.Timestamp(v.Modified.UTC().Format("2006-01-02T15:04:05.000-0700"))), Version: new(api.Version(versionName(v.Version))), RevisionId: new(api.String(v.Revision)), State: new(api.State(v.State)), PackageType: new(api.PackageType("Zip")), Architectures: api.ArchitecturesList{api.Architecture(v.Architecture)}, EphemeralStorage: &api.EphemeralStorage{Size: new(api.EphemeralStorageSize(v.EphemeralMB))}}
	if v.Image != nil {
		out.PackageType = new(api.PackageType("Image"))
		out.Runtime, out.Handler = nil, nil
		out.ImageConfigResponse = &api.ImageConfigResponse{ImageConfig: cloneImageConfig(v.ImageConfig)}
	}
	out.LoggingConfig = loggingConfiguration(v)
	out.TracingConfig = &api.TracingConfigResponse{Mode: new(api.TracingMode("PassThrough"))}
	out.DurableConfig = cloneDurableConfig(v.Durable)
	out.CapacityProviderConfig = capacityFunctionOutput(v.Capacity)
	out.VpcConfig = functionVpcConfig(v)
	if v.SigningProfileVersionARN != "" {
		out.SigningProfileVersionArn = new(api.Arn(v.SigningProfileVersionARN))
		out.SigningJobArn = new(api.Arn(v.SigningJobARN))
	}
	if v.Reference != nil && v.State == "Pending" && v.StateReasonCode == "Creating" {
		// Native REFERENCE creation exposes the digest only after readiness.
		out.CodeSha256 = new(api.String(""))
	}
	if v.UpdateStatus != "" {
		out.LastUpdateStatus = new(api.LastUpdateStatus(v.UpdateStatus))
	}
	if v.StateReason != "" {
		out.StateReason = new(api.StateReason(v.StateReason))
		out.StateReasonCode = new(api.StateReasonCode(v.StateReasonCode))
	}
	if v.UpdateReason != "" {
		out.LastUpdateStatusReason = new(api.LastUpdateStatusReason(v.UpdateReason))
	}
	if v.UpdateStatus == "InProgress" {
		out.LastUpdateStatusReasonCode = new(api.LastUpdateStatusReasonCode("Creating"))
	}
	if v.UpdateStatus == "Failed" {
		out.LastUpdateStatusReasonCode = new(api.LastUpdateStatusReasonCode("InternalError"))
	}
	if v.DeadLetterARN != "" {
		out.DeadLetterConfig = &api.DeadLetterConfig{TargetArn: new(api.ResourceArn(v.DeadLetterARN))}
	}
	if len(v.Variables) > 0 {
		out.Environment = &api.EnvironmentResponse{Variables: api.EnvironmentVariables{}}
		for k, value := range v.Variables {
			out.Environment.Variables[api.EnvironmentVariableName(k)] = api.EnvironmentVariableValue(value)
		}
	}
	for _, layer := range v.Layers {
		projection := api.Layer{Arn: new(api.LayerVersionArn(layer.Key.ARN())), CodeSize: new(api.Long(layer.CodeSize))}
		if layer.SigningProfileVersionARN != "" {
			projection.SigningProfileVersionArn = new(api.Arn(layer.SigningProfileVersionARN))
			projection.SigningJobArn = new(api.Arn(layer.SigningJobARN))
		}
		out.Layers = append(out.Layers, projection)
	}
	return out
}
func variables(in *api.Environment) (map[string]string, *awswire.Error) {
	out := map[string]string{}
	if in == nil {
		return out, nil
	}
	size := 0
	reserved := map[string]bool{"_HANDLER": true, "_X_AMZN_TRACE_ID": true, "AWS_DEFAULT_REGION": true, "AWS_REGION": true, "AWS_EXECUTION_ENV": true, "AWS_LAMBDA_FUNCTION_NAME": true, "AWS_LAMBDA_FUNCTION_MEMORY_SIZE": true, "AWS_LAMBDA_FUNCTION_VERSION": true, "AWS_LAMBDA_INITIALIZATION_TYPE": true, "AWS_LAMBDA_LOG_GROUP_NAME": true, "AWS_LAMBDA_LOG_STREAM_NAME": true, "AWS_ACCESS_KEY": true, "AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true, "AWS_LAMBDA_RUNTIME_API": true, "LAMBDA_TASK_ROOT": true, "LAMBDA_RUNTIME_DIR": true}
	for key, value := range in.Variables {
		k, v := string(key), string(value)
		if reserved[k] || !environmentName.MatchString(k) {
			return nil, failure("InvalidParameterValueException", "Invalid or reserved environment variable: "+k, 400)
		}
		size += len(k) + len(v)
		out[k] = v
	}
	if size > 4096 {
		return nil, failure("InvalidParameterValueException", "Environment variables exceed the 4 KB limit.", 400)
	}
	return out, nil
}
func validateDeployment(v FunctionRecord) *awswire.Error {
	if v.Image == nil && (v.Runtime == "" || v.Handler == "") {
		return failure("InvalidParameterValueException", "Runtime and Handler are required for ZIP functions.", 400)
	}
	if v.Image != nil && (v.Runtime != "" || v.Handler != "" || len(v.Layers) > 0 || v.Capacity != nil || v.Durable != nil) {
		return failure("InvalidParameterValueException", "Image functions cannot specify Runtime, Handler, Layers, managed capacity or durable configuration.", 400)
	}
	if v.Image == nil && v.ImageConfig != nil {
		return failure("InvalidParameterValueException", "ImageConfig is only valid for image functions.", 400)
	}
	if wire := validateImageConfig(v.ImageConfig); wire != nil {
		return wire
	}
	maxTimeout, maxMemory := 900, 10240
	if v.Capacity != nil {
		maxTimeout, maxMemory = 5400, 32768
	}
	if v.Timeout > maxTimeout {
		return failure("InvalidParameterValueException", fmt.Sprintf("Timeout exceeds the %d-second execution limit.", maxTimeout), 400)
	}
	if v.MemoryMB > maxMemory {
		return failure("InvalidParameterValueException", fmt.Sprintf("MemorySize exceeds the %d MB execution limit.", maxMemory), 400)
	}
	return nil
}

func validateTracingConfiguration(config *api.TracingConfig) *awswire.Error {
	if config == nil || value(config.Mode) == "" || value(config.Mode) == "PassThrough" {
		return nil
	}
	if value(config.Mode) == "Active" {
		return unsupported("Active Lambda X-Ray tracing is not implemented.")
	}
	return failure("InvalidParameterValueException", "Tracing mode must be Active or PassThrough.", 400)
}

func (s *Service) createFunction(ctx context.Context, in *api.CreateFunctionInput) (out *api.CreateFunctionOutput, wire *awswire.Error) {
	if in.Code.SourceKMSKeyArn != nil {
		return nil, unsupported("Customer-key code encryption is not implemented.")
	}
	packageImage := value(in.PackageType) == "Image"
	if value(in.PackageType) != "" && value(in.PackageType) != "Zip" && !packageImage {
		return nil, failure("InvalidParameterValueException", "PackageType must be Zip or Image.", 400)
	}
	if in.Code.ImageUri != nil && !packageImage {
		return nil, failure("InvalidParameterValueException", "ImageUri requires PackageType Image.", 400)
	}
	if packageImage && (in.Runtime != nil || in.Handler != nil || in.Code.ImageUri == nil || in.Code.ZipFile != nil || in.Code.S3Bucket != nil || in.Code.S3Key != nil || in.Code.S3ObjectVersion != nil || in.Code.S3ObjectStorageMode != nil || len(in.Layers) > 0 || in.CodeSigningConfigArn != nil) {
		return nil, failure("InvalidParameterValueException", "Image deployments require only Code.ImageUri and cannot specify Runtime, Handler, Layers or code signing.", 400)
	}
	if in.KMSKeyArn != nil || len(in.FileSystemConfigs) > 0 || in.SnapStart != nil || in.TenancyConfig != nil {
		return nil, unsupported("The requested advanced Lambda deployment configuration is not implemented.")
	}
	if wire := validateTracingConfiguration(in.TracingConfig); wire != nil {
		return nil, wire
	}
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	key := ref.FunctionKey
	if ref.Qualifier != "" {
		return nil, failure("InvalidParameterValueException", "CreateFunction requires an unqualified function name.", 400)
	}
	if key.Scope != scopeFor(ctx) {
		return nil, failure("InvalidParameterValueException", "A function must be created in the caller's account and request region.", 400)
	}
	vars, wire := variables(in.Environment)
	if wire != nil {
		return nil, wire
	}
	record := FunctionRecord{Key: key, Runtime: value(in.Runtime), Handler: value(in.Handler), Role: value(in.Role), Description: value(in.Description), Architecture: "x86_64", Variables: vars, Tags: map[string]string{}, Timeout: 3, MemoryMB: 128, EphemeralMB: 512, Revision: uuid.NewString(), Modified: s.clock.Now(), State: "Pending", StateReason: "The function is being created.", StateReasonCode: "Creating", UpdateStatus: "Successful"}
	record.DeploymentRevision = record.Revision
	record.Owner, wire = functionOwnerFor(ctx)
	if wire != nil {
		return nil, wire
	}
	if wire := applyDurableConfig(&record, in.DurableConfig, true); wire != nil {
		return nil, wire
	}
	if wire := s.validateDurableEncryption(ctx, &record); wire != nil {
		return nil, wire
	}
	if wire := configureLogging(&record, in.LoggingConfig); wire != nil {
		return nil, wire
	}
	if in.DeadLetterConfig != nil {
		record.DeadLetterARN = value(in.DeadLetterConfig.TargetArn)
	}
	if in.Timeout != nil {
		record.Timeout = int(*in.Timeout)
	}
	if in.MemorySize != nil {
		record.MemoryMB = int(*in.MemorySize)
	}
	if len(in.Architectures) > 0 {
		record.Architecture = string(in.Architectures[0])
	}
	if in.EphemeralStorage != nil && in.EphemeralStorage.Size != nil {
		record.EphemeralMB = int(*in.EphemeralStorage.Size)
	}
	for k, v := range in.Tags {
		record.Tags[string(k)] = string(v)
	}
	record.Capacity, wire = s.validateCapacityAssignment(ctx, in.CapacityProviderConfig, key.ARN(), record.Runtime, record.Architecture, record.MemoryMB)
	if wire != nil {
		return nil, wire
	}
	record.ImageConfig = cloneImageConfig(in.ImageConfig)
	if !packageImage {
		if wire := validateDeployment(record); wire != nil {
			return nil, wire
		}
	}
	conditions := layerConditions(in.Layers)
	if configARN := value(in.CodeSigningConfigArn); configARN != "" {
		if conditions == nil {
			conditions = map[string][]string{}
		}
		conditions["lambda:CodeSigningConfigArn"] = []string{configARN}
	}
	if wire := s.authorize(ctx, "CreateFunction", key.ARN(), nil, record.Tags, conditions); wire != nil {
		return nil, wire
	}
	if len(record.Tags) > 0 {
		if wire := s.authorize(ctx, "TagResource", key.ARN(), nil, record.Tags, nil); wire != nil {
			return nil, wire
		}
	}
	if wire := validateFunctionTags(record.Tags); wire != nil {
		return nil, wire
	}
	var archive CodeArchive
	var signing *codeSigningAdmission
	if packageImage {
		s.imageMu.Lock()
		defer s.imageMu.Unlock()
		defer s.finishImageStage(ctx, &wire)
		record.Image, record.CodeSHA256, wire = s.loadImage(ctx, value(in.Code.ImageUri), record.Architecture)
		if wire != nil {
			return nil, wire
		}
		record.CodeSize = record.Image.Size
		if wire := validateDeployment(record); wire != nil {
			return nil, wire
		}
	} else {
		var reference *S3ObjectReference
		archive, reference, wire = s.loadCode(ctx, key.Scope, key.ARN(), in.Code.ZipFile, value(in.Code.S3Bucket), value(in.Code.S3Key), value(in.Code.S3ObjectVersion), value(in.Code.S3ObjectStorageMode))
		if wire != nil {
			return nil, wire
		}
		record.CodeSHA256, record.CodeSize, record.Reference = archive.Key.SHA256, int64(len(archive.Code)), reference
		s.scheduleCodeSourceCheck(&record)
		record.Layers, wire = s.prepareLayers(ctx, key, layerStrings(in.Layers))
		if wire != nil {
			return nil, wire
		}
		signing, wire = s.prepareCodeSigning(ctx, key, value(in.CodeSigningConfigArn), archive.Code, record.Layers)
		if wire != nil {
			return nil, wire
		}
		signing.applyFunction(&record)
	}
	if s.executor == nil || s.roles == nil {
		return nil, unsupported("No Lambda container executor is configured.")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return nil, failure("ServiceException", "Lambda service is shutting down.", 503)
	}
	var response *api.FunctionConfiguration
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if wire := s.authorize(tx.Context(), "CreateFunction", key.ARN(), nil, record.Tags, conditions); wire != nil {
			return wire
		}
		if _, err := tx.Function(key); err == nil {
			return failure("ResourceConflictException", "Function already exists.", 409)
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		if wire := s.roles.Validate(tx.Context(), record.Role, key.ARN()); wire != nil {
			return wire
		}
		if wire := s.configureFunctionNetwork(tx.Context(), &record, in.VpcConfig); wire != nil {
			return wire
		}
		if wire := s.checkOutcomeTarget(tx.Context(), key, record.Role, record.DeadLetterARN, true, false); wire != nil {
			return wire
		}
		if wire := requireLayerCatalog(tx, record.Layers); wire != nil {
			return wire
		}
		if record.Image == nil {
			if wire := validateDeploymentCode(tx, archive.Code, record.Layers); wire != nil {
				return wire
			}
		}
		if err := s.validateCapacityFunction(tx, record); err != nil {
			return err
		}
		if record.Image == nil {
			if err := tx.PutCodeArchive(archive); err != nil {
				return err
			}
		}
		if err := tx.PutFunction(record); err != nil {
			return err
		}
		if err := signing.commit(tx, true); err != nil {
			return err
		}
		response = configuration(record)
		if in.Publish != nil && bool(*in.Publish) {
			var published FunctionRecord
			var err error
			if in.PublishTo != nil {
				published, _, err = publishCapacitySnapshot(tx, record, nil)
			} else {
				published, _, err = publishSnapshot(tx, record, nil)
			}
			if err != nil {
				return err
			}
			response = configuration(published)
			response.FunctionArn = new(api.NameSpacedFunctionArn(key.ARN()))
		}
		return s.recordCall(tx.Context(), "CreateFunction", in, response, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.work.Add(1)
	go func() { defer s.work.Done(); s.activate(record) }()
	return response, nil
}
func (s *Service) getConfiguration(ctx context.Context, in *api.GetFunctionConfigurationInput) (*api.GetFunctionConfigurationOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	var record FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		record, err = loadFunction(r, ref)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, "GetFunctionConfiguration", ref, record, nil); wire != nil {
			return wire
		}
		if record.Version == 0 {
			if pending, err := r.PendingFunction(ref.FunctionKey); err == nil {
				record = pending
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	out := configuration(record)
	out.FunctionArn = new(api.NameSpacedFunctionArn(ref.ARN()))
	return out, nil
}
func (s *Service) listFunctions(ctx context.Context, in *api.ListFunctionsInput) (*api.ListFunctionsOutput, *awswire.Error) {
	if in.MasterRegion != nil {
		return nil, unsupported("Replica listing is not implemented.")
	}
	all := value(in.FunctionVersion) == "ALL"
	if in.FunctionVersion != nil && !all {
		return nil, failure("InvalidParameterValueException", "FunctionVersion must be ALL.", 400)
	}
	scope := scopeFor(ctx)
	var records []FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if wire := s.authorize(r.Context(), "ListFunctions", "*", nil, nil, nil); wire != nil {
			return wire
		}
		var err error
		records, err = r.Functions(scope)
		if err != nil {
			return err
		}
		for i := range records {
			if pending, err := r.PendingFunction(records[i].Key); err == nil {
				records[i] = pending
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		if all {
			for _, latest := range records {
				versions, err := r.FunctionVersions(latest.Key)
				if err != nil {
					return err
				}
				records = append(records, versions...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	prefix := FunctionKey{Scope: scope}.ARN() + "/functions/" + value(in.FunctionVersion) + "/"
	functions, next, wire := functionPage(records, value(in.Marker), in.MaxItems, prefix, all)
	if wire != nil {
		return nil, wire
	}
	return &api.ListFunctionsOutput{Functions: functions, NextMarker: next}, nil
}
func (s *Service) deleteFunction(ctx context.Context, in *api.DeleteFunctionInput) (*api.DeleteFunctionOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), value(in.Qualifier))
	if wire != nil {
		return nil, wire
	}
	key := ref.FunctionKey
	var version uint64
	if ref.Qualifier == "$LATEST.PUBLISHED" {
		version = LatestPublishedVersion
	} else if ref.Qualifier != "" {
		var err error
		version, err = strconv.ParseUint(ref.Qualifier, 10, 64)
		if err != nil || version == 0 || version >= LatestPublishedVersion {
			return nil, failure("InvalidParameterValueException", "Only a numeric published version or $LATEST.PUBLISHED can be deleted with Qualifier.", 400)
		}
	}
	var networkSnapshot FunctionRecord
	if version == 0 {
		if err := s.repository.View(ctx, func(r Reader) error {
			var err error
			networkSnapshot, err = r.Function(key)
			if err != nil {
				return err
			}
			if wire := s.authorizeFunction(r, "DeleteFunction", ref, networkSnapshot, nil); wire != nil {
				return wire
			}
			return requireVersionOwner(r, ref)
		}); err != nil {
			return nil, wireError(err)
		}
		if err := s.recoverFunctionNetwork(ctx, networkSnapshot); err != nil {
			return nil, wireError(err)
		}
	}
	s.imageMu.Lock()
	s.mu.Lock()
	err := s.repository.Update(ctx, func(tx Transaction) error {
		record, err := tx.Function(key)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "DeleteFunction", ref, record, nil); wire != nil {
			return wire
		}
		if err := requireVersionOwner(tx, ref); err != nil {
			return err
		}
		if version == 0 && (record.NetworkIncarnation != networkSnapshot.NetworkIncarnation || record.DeploymentRevision != networkSnapshot.DeploymentRevision) {
			return failure("ResourceConflictException", "The function deployment changed during network cleanup.", 409)
		}
		if err := deleteCapacityFunctionScaling(tx, key, version); err != nil {
			return err
		}
		if version == 0 {
			if err := tx.DeleteFunction(key); err != nil {
				return err
			}
		} else {
			aliases, err := tx.Aliases(key)
			if err != nil {
				return err
			}
			for _, alias := range aliases {
				if alias.FunctionVersion == version || alias.AdditionalVersion == version {
					return failure("ResourceConflictException", "The version is referenced by an alias.", 409)
				}
			}
			// Only deleting the extant last-allocated publication invalidates
			// latest's revision; the highest surviving version is not a pointer.
			last, err := tx.LastAllocatedVersion(key)
			if err != nil {
				return err
			}
			if version == last {
				if _, err := tx.FunctionVersion(FunctionVersionKey{FunctionKey: key, Version: version}); err == nil {
					record.Revision = uuid.NewString()
					if err := tx.PutFunction(record); err != nil {
						return err
					}
				} else if !errors.Is(err, ErrNotFound) {
					return err
				}
			}
			if err := tx.DeleteFunctionVersion(FunctionVersionKey{FunctionKey: key, Version: version}); err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err := tx.DeleteProvisionedConcurrency(ref); err != nil {
				return err
			}
			if err := tx.DeleteRuntimeManagement(FunctionVersionKey{FunctionKey: key, Version: version}); err != nil {
				return err
			}
		}
		return s.recordCall(tx.Context(), "DeleteFunction", in, nil, nil)
	})
	var idle []*execution
	if err == nil {
		if version == 0 {
			s.reservationChanged(key, false)
			idle = s.retireFunctionExecutionsLocked(key)
		} else {
			idle = s.retireExecutionsLocked(FunctionVersionKey{FunctionKey: key, Version: version}, nil)
		}
	}
	s.mu.Unlock()
	s.imageMu.Unlock()
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	s.provisionedChanged()
	s.closeIdleExecutions(idle)
	var retentionWire *awswire.Error
	s.imageMu.Lock()
	s.finishImageStage(ctx, &retentionWire)
	s.imageMu.Unlock()
	if retentionWire != nil {
		return &api.DeleteFunctionOutput{StatusCode: new(api.Integer(204))}, retentionWire
	}
	return &api.DeleteFunctionOutput{StatusCode: new(api.Integer(204))}, nil
}
