package stepfunctions

import (
	"context"
	"fmt"
	"slices"
	"strings"

	api "stackd/internal/awsapi/stepfunctions"
	"stackd/internal/services/stepfunctions/asl"
)

func workflowType(input *api.StateMachineType) (string, error) {
	if input == nil {
		return "STANDARD", nil
	}
	typ := value(input)
	if typ != "STANDARD" && typ != "EXPRESS" {
		return "", invalid("type must be STANDARD or EXPRESS.")
	}
	return typ, nil
}

func definitionInput(input *api.Definition) error {
	if input == nil || len(*input) == 0 || len(*input) > 1048576 {
		return invalid("definition must contain between 1 and 1048576 bytes.")
	}
	return nil
}

func compileWorkflow(source, typ string) (*asl.Definition, []asl.Diagnostic) {
	definition, diagnostics := asl.Compile(source)
	if definition == nil || typ != "EXPRESS" {
		return definition, diagnostics
	}
	var visit func(*asl.Definition, string)
	visit = func(def *asl.Definition, path string) {
		names := make([]string, 0, len(def.States))
		for name := range def.States {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			state := def.States[name]
			location := path + "/States/" + strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
			if state.Task != nil {
				resource := state.Task.Resource
				if strings.Contains(resource, ":activity:") || strings.HasSuffix(resource, ".sync") || strings.HasSuffix(resource, ".sync:2") || strings.HasSuffix(resource, ".waitForTaskToken") {
					diagnostics = append(diagnostics, asl.Diagnostic{Severity: "ERROR", Code: "SCHEMA_VALIDATION_FAILED", Location: location + "/Resource", Message: "Express workflows do not support activities, .sync, or .waitForTaskToken integrations."})
				}
			}
			if state.Map != nil {
				if state.Map.ProcessorConfig.Mode == "DISTRIBUTED" {
					diagnostics = append(diagnostics, asl.Diagnostic{Severity: "ERROR", Code: "SCHEMA_VALIDATION_FAILED", Location: location + "/ItemProcessor/ProcessorConfig", Message: "Distributed Map is not supported in Express workflows."})
				}
				visit(state.Map.Processor, location+"/ItemProcessor")
			}
			if state.Parallel != nil {
				for i, branch := range state.Parallel.Branches {
					visit(branch, fmt.Sprintf("%s/Branches/%d", location, i))
				}
			}
		}
	}
	visit(definition, "")
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "ERROR" {
			return nil, diagnostics
		}
	}
	return definition, diagnostics
}

func admitDefinition(input *api.Definition, typ string) (*asl.Definition, error) {
	if err := definitionInput(input); err != nil {
		return nil, err
	}
	definition, diagnostics := compileWorkflow(value(input), typ)
	if definition == nil {
		messages := make([]string, 0, len(diagnostics))
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity == "ERROR" {
				messages = append(messages, diagnostic.Code+": "+diagnostic.Message+" at "+diagnostic.Location)
			}
		}
		return nil, failure("InvalidDefinition", "Invalid State Machine Definition: '"+strings.Join(messages, ", ")+"'", 400)
	}
	return definition, nil
}

func (s *Service) validateStateMachineDefinition(tx Transaction, in *api.ValidateStateMachineDefinitionInput) (*api.ValidateStateMachineDefinitionOutput, error) {
	if rejected := s.authorize(tx, "ValidateStateMachineDefinition", "*", nil, nil); rejected != nil {
		return nil, rejected
	}
	if err := definitionInput(in.Definition); err != nil {
		return nil, err
	}
	typ, err := workflowType(in.Type)
	if err != nil {
		return nil, err
	}
	severity := value(in.Severity)
	if in.Severity == nil {
		severity = "ERROR"
	}
	if severity != "ERROR" && severity != "WARNING" {
		return nil, invalid("severity must be ERROR or WARNING.")
	}
	limit := 100
	if in.MaxResults != nil {
		if *in.MaxResults < 0 || *in.MaxResults > 100 {
			return nil, invalid("maxResults must be between 0 and 100.")
		}
		if *in.MaxResults > 0 {
			limit = int(*in.MaxResults)
		}
	}
	definition, diagnostics := compileWorkflow(value(in.Definition), typ)
	out := &api.ValidateStateMachineDefinitionOutput{Diagnostics: api.ValidateStateMachineDefinitionDiagnosticList{}, Result: new(api.ValidateStateMachineDefinitionResultCodeOK), Truncated: new(api.ValidateStateMachineDefinitionTruncated(false))}
	if definition == nil {
		out.Result = new(api.ValidateStateMachineDefinitionResultCodeFAIL)
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "WARNING" && severity == "ERROR" {
			continue
		}
		if len(out.Diagnostics) == limit {
			out.Truncated = new(api.ValidateStateMachineDefinitionTruncated(true))
			break
		}
		item := api.ValidateStateMachineDefinitionDiagnostic{Code: new(api.ValidateStateMachineDefinitionCode(diagnostic.Code)), Message: new(api.ValidateStateMachineDefinitionMessage(diagnostic.Message)), Severity: new(api.ValidateStateMachineDefinitionSeverity(diagnostic.Severity))}
		if diagnostic.Location != "" {
			item.Location = new(api.ValidateStateMachineDefinitionLocation(diagnostic.Location))
		}
		out.Diagnostics = append(out.Diagnostics, item)
	}
	return out, nil
}

func (s *Service) admitConfiguration(ctx context.Context, revision *RevisionRecord, logging *api.LoggingConfiguration, tracing *api.TracingConfiguration, encryption *api.EncryptionConfiguration) error {
	if logging != nil {
		level := value(logging.Level)
		if level != "OFF" && level != "ALL" && level != "ERROR" && level != "FATAL" {
			return failure("InvalidLoggingConfiguration", "Logging level must be OFF, ALL, ERROR, or FATAL.", 400)
		}
		if len(logging.Destinations) > 1 || level != "OFF" && len(logging.Destinations) != 1 {
			return failure("InvalidLoggingConfiguration", "Exactly one CloudWatch Logs destination is required when logging is enabled.", 400)
		}
		revision.LogLevel, revision.LogGroupARN, revision.IncludeExecutionData = level, "", false
		if len(logging.Destinations) == 1 {
			group := logging.Destinations[0].CloudWatchLogsLogGroup
			if group == nil || !strings.HasSuffix(value(group.LogGroupArn), ":*") {
				return failure("InvalidLoggingConfiguration", "The CloudWatch Logs log group ARN must end with :*.", 400)
			}
			revision.LogGroupARN = value(group.LogGroupArn)
		}
		if logging.IncludeExecutionData != nil {
			revision.IncludeExecutionData = bool(*logging.IncludeExecutionData)
		}
	}
	if tracing != nil {
		revision.TracingEnabled = tracing.Enabled != nil && bool(*tracing.Enabled)
		if revision.TracingEnabled && s.tracing == nil {
			return fmt.Errorf("enabled tracing requires the Step Functions X-Ray dependency")
		}
	}
	return s.admitEncryption(ctx, &revision.EncryptionConfig, encryption)
}

func (s *Service) admitEncryption(ctx context.Context, config *EncryptionConfig, encryption *api.EncryptionConfiguration) error {
	if encryption == nil {
		return nil
	}
	switch value(encryption.Type) {
	case "AWS_OWNED_KEY":
		if encryption.KmsKeyId != nil {
			return failure("InvalidEncryptionConfiguration", "Invalid Encryption Configuration: Custom kmsKeyId is not allowed when selecting AWS_OWNED_KEY.", 400)
		}
		if encryption.KmsDataKeyReusePeriodSeconds != nil {
			return failure("InvalidEncryptionConfiguration", "Invalid Encryption Configuration: Custom kmsDataKeyReusePeriodSeconds is not allowed when selecting AWS_OWNED_KEY.", 400)
		}
		*config = EncryptionConfig{EncryptionType: "AWS_OWNED_KEY"}
	case "CUSTOMER_MANAGED_KMS_KEY":
		if value(encryption.KmsKeyId) == "" {
			return failure("InvalidEncryptionConfiguration", "Invalid Encryption Configuration: Must set a valid kmsKeyId.", 400)
		}
		reuse := int64(300)
		if encryption.KmsDataKeyReusePeriodSeconds != nil {
			reuse = int64(*encryption.KmsDataKeyReusePeriodSeconds)
		}
		if reuse < 60 || reuse > 900 {
			return invalid("kmsDataKeyReusePeriodSeconds must be between 60 and 900.")
		}
		if s.encryption.keys == nil {
			return fmt.Errorf("step functions encryption keys are not configured")
		}
		key, rejected := s.encryption.keys.ResolveKey(ctx, value(encryption.KmsKeyId))
		if rejected != nil {
			return rejected
		}
		*config = EncryptionConfig{EncryptionType: "CUSTOMER_MANAGED_KMS_KEY", KMSKeyARN: key, DataKeyReuseSeconds: reuse}
	default:
		return invalid("encryptionConfiguration.type must be AWS_OWNED_KEY or CUSTOMER_MANAGED_KMS_KEY.")
	}
	return nil
}

func needsNestedSync(definition *asl.Definition) bool {
	return needsSyncResource(definition, "states:startExecution.sync", "states:startExecution.sync:2")
}

func needsECSSync(definition *asl.Definition) bool {
	return needsSyncResource(definition, "ecs:runTask.sync")
}

func needsSyncResource(definition *asl.Definition, resources ...string) bool {
	for _, state := range definition.States {
		if state.Task != nil {
			parts := strings.SplitN(state.Task.Resource, ":", 6)
			if len(parts) == 6 && parts[2] == "states" {
				for _, resource := range resources {
					if parts[5] == resource {
						return true
					}
				}
			}
		}
		if state.Map != nil && needsSyncResource(state.Map.Processor, resources...) {
			return true
		}
		if state.Parallel != nil {
			for _, branch := range state.Parallel.Branches {
				if needsSyncResource(branch, resources...) {
					return true
				}
			}
		}
	}
	return false
}

func (s *Service) configureLogging(ctx context.Context, revision RevisionRecord) error {
	if revision.LogLevel == "" || revision.LogLevel == "OFF" {
		return nil
	}
	if s.history == nil {
		return failure("NotImplementedException", "CloudWatch Logs delivery is not configured.", 501)
	}
	return s.history.ConfigureLogging(ctx, revision)
}

func loggingOutput(revision RevisionRecord) *api.LoggingConfiguration {
	out := &api.LoggingConfiguration{Level: new(api.LogLevel(revision.LogLevel)), IncludeExecutionData: new(api.IncludeExecutionData(revision.IncludeExecutionData))}
	if revision.LogGroupARN != "" {
		out.Destinations = api.LogDestinationList{{CloudWatchLogsLogGroup: &api.CloudWatchLogsLogGroup{LogGroupArn: new(api.Arn(revision.LogGroupARN))}}}
	}
	return out
}

func encryptionOutput(revision EncryptionConfig) *api.EncryptionConfiguration {
	out := &api.EncryptionConfiguration{Type: new(api.EncryptionType(revision.EncryptionType))}
	if revision.KMSKeyARN != "" {
		out.KmsKeyId = new(api.KmsKeyId(revision.KMSKeyARN))
		out.KmsDataKeyReusePeriodSeconds = new(api.KmsDataKeyReusePeriodSeconds(revision.DataKeyReuseSeconds))
	}
	return out
}
