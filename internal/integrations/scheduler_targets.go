package integrations

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/internal/awsapi"
	codepipelineapi "stackd/internal/awsapi/codepipeline"
	ecsapi "stackd/internal/awsapi/ecs"
	eventsapi "stackd/internal/awsapi/eventbridge"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	scheduler "stackd/internal/services/scheduler"
)

// SchedulerTargets reuses the concrete assembled command owners; it never
// executes arbitrary host commands or fabricates a missing service's success.
type SchedulerTargets struct {
	Commands StepFunctionsCommands
	Roles    ServiceRoles
}

func schedulerSource(k scheduler.ScheduleKey) awsctx.ServicePrincipal {
	return awsctx.ServicePrincipal{
		Name:      "scheduler.amazonaws.com",
		SourceARN: k.Group.ARN(),
		Type:      "AWSService",
	}
}

func (a SchedulerTargets) ValidateRole(ctx context.Context, k scheduler.ScheduleKey, roleARN string) *awswire.Error {
	if a.Roles.IAM == nil || a.Roles.Authorizer == nil {
		return schedulerUnsupported("Scheduler role authority is not configured.")
	}
	var rejected *awswire.Error
	err := a.Roles.IAM.WithSession(ctx, func(ctx context.Context, _ identity.Repository, now time.Time) error {
		role, err := a.Roles.IAM.RoleForAssumption(ctx, roleARN)
		if err != nil {
			rejected = schedulerInvalid("The execution role does not exist.")
			return nil
		}
		ctx = awsctx.WithServicePrincipal(ctx, schedulerSource(k))
		if denied := a.Roles.trust(ctx, role, identity.RoleSessionSpec{SessionName: "Amazon_EventBridge_Scheduler"}, now, ""); denied != nil {
			rejected = schedulerInvalid("The execution role you provide must allow AWS EventBridge Scheduler to assume the role.")
			rejected.Cause = denied
		}
		return nil
	})
	if err != nil {
		return serviceRoleFailure(err)
	}
	return rejected
}

func (a SchedulerTargets) executionContext(ctx context.Context, k scheduler.ScheduleKey, roleARN string) (context.Context, *awswire.Error) {
	credential, rejected := a.Roles.assume(ctx, schedulerSource(k), roleARN, identity.RoleSessionSpec{SessionName: "Amazon_EventBridge_Scheduler"}, "")
	if rejected != nil {
		return nil, rejected
	}
	return serviceRoleRequestContext(ctx, credential, k.Group.Region, "scheduler.amazonaws.com")
}

func schedulerInvalid(message string) *awswire.Error {
	return &awswire.Error{
		Code:       "ValidationException",
		Message:    message,
		StatusCode: 400,
	}
}

func schedulerUnsupported(message string) *awswire.Error {
	return &awswire.Error{
		Code:       "NotImplementedException",
		Message:    message,
		StatusCode: 501,
	}
}

func schedulerTarget(arnText string) (service, operation string, universal bool, rejected *awswire.Error) {
	target, err := arn.Parse(arnText)
	if err != nil {
		return "", "", false, schedulerInvalid("Invalid target ARN.")
	}
	if target.Service == "scheduler" {
		parts := strings.Split(target.Resource, ":")
		if len(parts) != 3 || parts[0] != "aws-sdk" || target.Region != "" || target.AccountID != "" {
			return "", "", false, schedulerInvalid("Invalid universal target ARN.")
		}
		service, operation = parts[1], parts[2]
		if operation != "" && operation[0] >= 'A' && operation[0] <= 'Z' {
			operation = strings.ToLower(operation[:1]) + operation[1:]
		}
		for _, prefix := range []string{
			"get",
			"describe",
			"list",
			"poll",
			"receive",
			"search",
			"scan",
			"query",
			"select",
			"read",
			"lookup",
			"discover",
			"validate",
			"batchGet",
			"batchDescribe",
			"batchRead",
			"transactGet",
			"adminGet",
			"adminList",
			"testMigration",
			"retrieve",
			"testConnection",
			"translateDocument",
			"isAuthorized",
			"invokeModel",
		} {
			if strings.HasPrefix(operation, prefix) {
				return "", "", true, schedulerInvalid("Read-only and excluded API actions are not supported as Scheduler targets.")
			}
		}
		switch service {
		case "sfn":
			service = "stepfunctions"
		case "eventbridge":
			service = "eventbridge"
		case "cognitoidentityprovider":
			service = "cognitoidp"
		}
		return service, operation, true, nil
	}
	switch target.Service {
	case "sqs":
		return "sqs", "SendMessage", false, nil
	case "lambda":
		return "lambda", "Invoke", false, nil
	case "events":
		return "eventbridge", "PutEvents", false, nil
	case "sns":
		return "sns", "Publish", false, nil
	case "states":
		return "stepfunctions", "StartExecution", false, nil
	case "kinesis":
		return "kinesis", "PutRecord", false, nil
	case "firehose":
		return "firehose", "PutRecord", false, nil
	case "ecs":
		return "ecs", "RunTask", false, nil
	case "codebuild":
		return "codebuild", "StartBuild", false, nil
	case "codepipeline":
		return "codepipeline", "StartPipelineExecution", false, nil
	case "inspector", "sagemaker":
		// TODO: Comeback connect these templated targets when their genuine service execution owners exist.
		return "", "", false, schedulerUnsupported("The templated target service is not implemented: " + target.Service)
	default:
		return "", "", false, schedulerInvalid("Unsupported templated target ARN.")
	}
}

// Native CodePipeline templates ignore Target.Input. The translated request also
// owns the DLQ body, unlike targets that consume the original notification.
func schedulerCodePipelineParameters(name string) []byte {
	body, _ := json.Marshal(struct{ Name string }{Name: name})
	return body
}

func (a SchedulerTargets) ValidateTarget(ctx context.Context, k scheduler.ScheduleKey, t scheduler.TargetRecord) *awswire.Error {
	service, operation, universal, rejected := schedulerTarget(t.ARN)
	if rejected != nil {
		return rejected
	}
	target, _ := arn.Parse(t.ARN)
	if target.Partition != k.Group.Partition {
		return schedulerInvalid("Target ARN must use the schedule's partition.")
	}
	if !universal && service == "eventbridge" && target.Region != k.Group.Region {
		return schedulerInvalid("Cross-region EventBridge templated target delivery is not supported.")
	}
	provider, result, rejected := a.Commands.resolve(service, operation)
	if rejected != nil {
		return rejected
	}
	if ops, ok := provider.executor.(interface{ Operations() []string }); ok {
		implemented := false
		for _, op := range ops.Operations() {
			if op == string(result.Operation.Name) {
				implemented = true
				break
			}
		}
		if !implemented {
			return schedulerUnsupported("Target operation is not implemented: " + service + ":" + operation)
		}
	}
	if t.DeadLetterARN != "" {
		d, err := arn.Parse(t.DeadLetterARN)
		if err != nil || d.Service != "sqs" || d.Region != k.Group.Region || d.Partition != k.Group.Partition || strings.HasSuffix(d.Resource, ".fifo") {
			return schedulerInvalid("Dead letter queue must be a standard SQS queue in this Region.")
		}
	}
	if universal {
		if t.ECS != nil || t.HasSQS || t.HasEventBridge || t.HasKinesis {
			return schedulerInvalid("Templated target parameters cannot be used with a universal target.")
		}
		if !t.HasInput || !json.Valid([]byte(t.Input)) {
			return schedulerInvalid("Universal targets require a valid JSON Input.")
		}
		input, err := awscommands.NewInput(result.Service.Name, string(result.Operation.Name))
		if err != nil {
			return schedulerUnsupported(err.Error())
		}
		if err = awsapi.DecodeSDKInput(result.Service, result.Operation, []byte(t.Input), input); err != nil {
			return schedulerInvalid(err.Error())
		}
		return nil
	}
	if t.HasSQS && service != "sqs" || t.HasEventBridge && service != "eventbridge" || t.HasKinesis && service != "kinesis" || t.ECS != nil && service != "ecs" {
		return schedulerInvalid("Target parameters do not match target service.")
	}
	switch service {
	case "codepipeline":
		var input codepipelineapi.StartPipelineExecutionInput
		if err := awsapi.DecodeSDKInput(result.Service, result.Operation, schedulerCodePipelineParameters(target.Resource), &input); err != nil {
			return schedulerInvalid("Provided Arn is not in correct format.")
		}
	case "sqs":
		if strings.HasSuffix(target.Resource, ".fifo") && t.MessageGroupID == "" {
			return schedulerInvalid("FIFO queue targets require a MessageGroupId.")
		}
	case "eventbridge":
		if !t.HasEventBridge || t.EventSource == "" || t.EventDetailType == "" {
			return schedulerInvalid("EventBridgeParameters are required.")
		}
		if !strings.HasPrefix(target.Resource, "event-bus/") {
			return schedulerInvalid("Target must identify an EventBridge event bus.")
		}
	case "kinesis":
		if !t.HasKinesis || t.PartitionKey == "" {
			return schedulerInvalid("KinesisParameters are required.")
		}
	case "ecs":
		if t.ECS == nil || t.ECS.TaskDefinitionARN == "" {
			return schedulerInvalid("EcsParameters are required.")
		}
	}
	if service == "lambda" || service == "stepfunctions" || service == "eventbridge" {
		if t.HasInput && !json.Valid([]byte(t.Input)) {
			return schedulerInvalid("Target Input must be valid JSON.")
		}
	}
	return nil
}

func (a SchedulerTargets) Send(ctx context.Context, d scheduler.DeliveryRecord, payload string, deadLetter bool) *awswire.Error {
	ctx, rejected := a.executionContext(ctx, d.Schedule, d.Target.RoleARN)
	if rejected != nil {
		return rejected
	}
	t := d.Target
	if deadLetter {
		if original, err := arn.Parse(t.ARN); err == nil && original.Service == "codepipeline" {
			payload = string(schedulerCodePipelineParameters(original.Resource))
		}
		t.ARN = t.DeadLetterARN
		t.MessageGroupID = ""
	}
	service, operation, universal, rejected := schedulerTarget(t.ARN)
	if rejected != nil {
		return rejected
	}
	if universal && !deadLetter {
		_, rejected = a.Commands.Call(ctx, service, operation, json.RawMessage(payload))
		return rejected
	}
	target, _ := arn.Parse(t.ARN)
	m := awsctx.FromContext(ctx)
	m.Region = target.Region
	ctx = awsctx.WithMetadata(ctx, m)
	if service == "codepipeline" {
		if target.AccountID != m.AccountID {
			// TODO: Comeback calibrate cross-account CodePipeline templated delivery.
			// A name-only API must not silently start this role's same-named pipeline.
			return schedulerUnsupported("Cross-account CodePipeline templated targets are not implemented.")
		}
		input := &codepipelineapi.StartPipelineExecutionInput{
			Name: new(codepipelineapi.PipelineName(target.Resource)),
		}
		_, rejected = a.Commands.CallTyped(ctx, service, operation, input)
		return rejected
	}
	p := map[string]any{}
	switch service {
	case "sqs":
		p["QueueUrl"] = "https://sqs." + target.Region + ".amazonaws.com/" + target.AccountID + "/" + target.Resource
		p["MessageBody"] = payload
		if t.MessageGroupID != "" {
			p["MessageGroupId"] = t.MessageGroupID
		}
		if deadLetter {
			// TODO: Comeback implement native payload-truncation and retry-exhaustion attributes.
			attrs := map[string]any{}
			for k, v := range map[string]string{
				"ERROR_CODE":     d.LastErrorCode,
				"ERROR_MESSAGE":  d.LastErrorMessage,
				"SCHEDULE_ARN":   d.Schedule.ARN(),
				"TARGET_ARN":     d.Target.ARN,
				"RETRY_ATTEMPTS": strconv.Itoa(max(0, d.Attempts-1)),
				"SCHEDULED_TIME": d.Scheduled.UTC().Format(time.RFC3339),
				"EXECUTION_ID":   d.ExecutionID(),
			} {
				attrs[k] = map[string]string{
					"DataType":    "String",
					"StringValue": v,
				}
			}
			p["MessageAttributes"] = attrs
		}
	case "lambda":
		input := &lambdaapi.InvokeInput{
			FunctionName:   new(lambdaapi.NamespacedFunctionName(t.ARN)),
			InvocationType: new(lambdaapi.InvocationType("Event")),
			Payload:        []byte(payload),
		}
		_, rejected = a.Commands.CallTyped(ctx, service, operation, input)
		return rejected
	case "eventbridge":
		p["Entries"] = []any{map[string]any{
			"EventBusName": t.ARN,
			"Source":       t.EventSource,
			"DetailType":   t.EventDetailType,
			"Detail":       payload,
			"Time":         d.Scheduled.UTC().Format(time.RFC3339),
		}}
	case "sns":
		p["TopicArn"] = t.ARN
		p["Message"] = payload
	case "stepfunctions":
		p["StateMachineArn"] = t.ARN
		p["Input"] = payload
	case "kinesis":
		p["StreamARN"] = t.ARN
		p["PartitionKey"] = t.PartitionKey
		p["Data"] = payload
	case "firehose":
		p["DeliveryStreamName"] = strings.TrimPrefix(target.Resource, "deliverystream/")
		p["Record"] = map[string]string{"Data": payload}
	case "codebuild":
		p["ProjectName"] = strings.TrimPrefix(target.Resource, "project/")
		if t.HasInput {
			if err := json.Unmarshal([]byte(payload), &p); err != nil {
				return schedulerInvalid(err.Error())
			}
			if p == nil {
				return schedulerInvalid("CodeBuild target Input must be a non-null JSON object.")
			}
			p["ProjectName"] = strings.TrimPrefix(target.Resource, "project/")
		}
	case "ecs":
		var err error
		p, err = schedulerECS(t, payload)
		if err != nil {
			return schedulerInvalid("Invalid ECS task overrides: " + err.Error())
		}
		p["Cluster"] = t.ARN
	default:
		return schedulerUnsupported("Target dependency is not implemented.")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return schedulerInvalid(err.Error())
	}
	result, rejected := a.Commands.Call(ctx, service, operation, raw)
	if rejected != nil {
		return rejected
	}
	switch out := result.Output.(type) {
	case *eventsapi.PutEventsOutput:
		for _, entry := range out.Entries {
			if entry.ErrorCode != nil {
				return &awswire.Error{
					Code:       string(*entry.ErrorCode),
					Message:    schedulerValue(entry.ErrorMessage),
					StatusCode: 500,
				}
			}
		}
	case *ecsapi.RunTaskOutput:
		if len(out.Failures) > 0 {
			return &awswire.Error{
				Code:       "TargetError",
				Message:    schedulerValue(out.Failures[0].Reason),
				StatusCode: 500,
			}
		}
	}
	return nil
}

func schedulerValue[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}

func schedulerECS(t scheduler.TargetRecord, payload string) (map[string]any, error) {
	e := t.ECS
	p := map[string]any{
		"TaskDefinition": e.TaskDefinitionARN,
		"Count":          e.TaskCount,
	}
	if e.HasManagedTags {
		p["EnableECSManagedTags"] = e.ManagedTags
	}
	if e.HasExecuteCommand {
		p["EnableExecuteCommand"] = e.ExecuteCommand
	}
	for k, v := range map[string]string{
		"Group":           e.Group,
		"LaunchType":      e.LaunchType,
		"PlatformVersion": e.PlatformVersion,
		"PropagateTags":   e.PropagateTags,
		"ReferenceId":     e.ReferenceID,
	} {
		if v != "" {
			p[k] = v
		}
	}
	if e.HasNetwork {
		n := map[string]any{"Subnets": e.Subnets}
		if len(e.SecurityGroups) > 0 {
			n["SecurityGroups"] = e.SecurityGroups
		}
		if e.AssignPublicIP != "" {
			n["AssignPublicIp"] = e.AssignPublicIP
		}
		p["NetworkConfiguration"] = map[string]any{"AwsvpcConfiguration": n}
	}
	if len(e.Capacity) > 0 {
		items := []any{}
		for _, v := range e.Capacity {
			item := map[string]any{"CapacityProvider": v.Name}
			if v.HasBase {
				item["Base"] = v.Base
			}
			if v.HasWeight {
				item["Weight"] = v.Weight
			}
			items = append(items, item)
		}
		p["CapacityProviderStrategy"] = items
	}
	if len(e.Constraints) > 0 {
		items := []any{}
		for _, v := range e.Constraints {
			items = append(items, map[string]string{
				"Type":       v.Type,
				"Expression": v.Expression,
			})
		}
		p["PlacementConstraints"] = items
	}
	if len(e.Placement) > 0 {
		items := []any{}
		for _, v := range e.Placement {
			items = append(items, map[string]string{
				"Type":  v.Type,
				"Field": v.Field,
			})
		}
		p["PlacementStrategy"] = items
	}
	if len(e.Tags) > 0 {
		items := []any{}
		for _, v := range e.Tags {
			items = append(items, map[string]string{
				"Key":   v.Key,
				"Value": v.Value,
			})
		}
		p["Tags"] = items
	}
	if t.HasInput {
		var overrides any
		if err := json.Unmarshal([]byte(payload), &overrides); err != nil {
			return nil, err
		}
		p["Overrides"] = overrides
	}
	return p, nil
}
