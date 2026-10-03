package ec2

import (
	"context"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const lambdaManagedOperator = "scaler.lambda.amazonaws.com"

type lambdaManagedLaunchKey struct{}
type lambdaManagedTerminationKey struct{}

// RunLambdaManagedInstance enters ordinary EC2 admission under the current
// assumed operator role. The private marker supplies managed-resource conditions
// and immutable ownership before the initial instance transaction commits.
func (s *Service) RunLambdaManagedInstance(ctx context.Context, providerARN string, input *api.RunInstancesRequest) (*api.Reservation, *awswire.Error) {
	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation("RunInstances")
	request := awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}
	err := requireLambdaServiceSource(ctx, providerARN, "capacity-provider:")
	if err == nil && (input == nil || str(input.ClientToken) == "" || input.MinCount == nil || input.MaxCount == nil || *input.MinCount != 1 || *input.MaxCount != 1) {
		err = failure("InvalidParameterValue", "A Lambda managed launch requires one instance and an immutable guest generation ClientToken.")
	}
	if err != nil {
		rejected := wireError(err)
		if err := s.RecordRequestError(ctx, request, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	out, rejected := s.ExecuteCommand(context.WithValue(ctx, lambdaManagedLaunchKey{}, providerARN), request)
	if rejected != nil {
		return nil, rejected
	}
	result, ok := out.(*api.Reservation)
	if !ok {
		return nil, failure("InternalError", "Invalid EC2 RunInstances result.")
	}
	return result, nil
}

// TerminateLambdaManagedInstance can only mutate exact instances belonging to
// this provider, using the current Lambda service-linked role and normal IAM.
func (s *Service) TerminateLambdaManagedInstance(ctx context.Context, providerARN string, input *api.TerminateInstancesRequest) (*api.TerminateInstancesResult, *awswire.Error) {
	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation("TerminateInstances")
	request := awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input}
	err := requireLambdaServiceSource(ctx, providerARN, "capacity-provider:")
	m := awsctx.FromContext(ctx)
	if err == nil && m.IssuerARN != "arn:"+m.Partition+":iam::"+m.AccountID+":role/aws-service-role/lambda.amazonaws.com/AWSServiceRoleForLambda" {
		err = failure("AuthFailure", "Lambda managed termination requires the Lambda service-linked role.")
	}
	if err == nil && input == nil {
		err = failure("MissingParameter", "An instance termination request is required.")
	}
	if err != nil {
		rejected := wireError(err)
		if err := s.RecordRequestError(ctx, request, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	out, rejected := s.ExecuteCommand(context.WithValue(ctx, lambdaManagedTerminationKey{}, providerARN), request)
	if rejected != nil {
		return nil, rejected
	}
	result, ok := out.(*api.TerminateInstancesResult)
	if !ok {
		return nil, failure("InternalError", "Invalid EC2 TerminateInstances result.")
	}
	return result, nil
}

func addLambdaManagedLaunchConditions(ctx context.Context, action, kind string, conditions map[string][]string) {
	if _, managed := ctx.Value(lambdaManagedLaunchKey{}).(string); !managed {
		return
	}
	if (action == "RunInstances" || action == "CreateTags") && (kind == "instance" || kind == "volume" || kind == "network-interface") {
		conditions["ec2:ManagedResourceOperator"] = []string{lambdaManagedOperator}
	}
}

func lambdaInstanceOperator(record InstanceRecord) *api.OperatorResponse {
	if record.LambdaCapacityProviderARN == "" {
		return unmanagedInstanceOperator()
	}
	return &api.OperatorResponse{Managed: new(api.Boolean(true)), HiddenByDefault: new(api.Boolean(false)), Principal: new(api.String(lambdaManagedOperator))}
}

func validateLambdaInstanceCommand(ctx context.Context, action string, record InstanceRecord, conditions map[string][]string) error {
	provider, termination := ctx.Value(lambdaManagedTerminationKey{}).(string)
	if termination && (action != "TerminateInstances" || record.LambdaCapacityProviderARN != provider || record.LambdaManagedGeneration == "") {
		return failure("AuthFailure", "The instance is not owned by this Lambda capacity provider.")
	}
	if record.LambdaCapacityProviderARN != "" {
		conditions["ec2:ManagedResourceOperator"] = []string{lambdaManagedOperator}
		if !termination && !strings.HasPrefix(action, "Describe") && !strings.HasPrefix(action, "Get") {
			return failure("OperationNotPermitted", "Lambda manages this instance's lifecycle.")
		}
	}
	return nil
}

func validateLambdaReservation(ctx context.Context, tx Reader, record ReservationRecord) error {
	provider, managed := ctx.Value(lambdaManagedLaunchKey{}).(string)
	for _, id := range record.InstanceIDs {
		instance, err := tx.Instance(key(ctx, id))
		if err != nil {
			return err
		}
		if managed != (instance.LambdaCapacityProviderARN != "") || managed && (instance.LambdaCapacityProviderARN != provider || instance.LambdaManagedGeneration != record.ClientToken) {
			return networkInterfaceTokenMismatch()
		}
	}
	if managed {
		// Session names can change on renewal; the immutable IAM role ID cannot.
		previous, _, _ := strings.Cut(record.LaunchPrincipalID, ":")
		current, _, _ := strings.Cut(awsctx.FromContext(ctx).PrincipalID, ":")
		if previous != current {
			return failure("AuthFailure", "The launch belongs to a different IAM role identity.")
		}
	}
	return nil
}
