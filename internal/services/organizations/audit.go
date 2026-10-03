package organizations

import (
	"context"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Organizations is a global management API. Classification is an explicit
// service contract, not a name-prefix rule. The native DescribeOrganization
// capture confirms read-only response suppression; the Organizations CloudTrail
// documentation supplies write response examples and acting-account scope.
func readOnlyOperation(action string) bool {
	switch action {
	case "DescribeAccount", "DescribeCreateAccountStatus", "DescribeEffectivePolicy",
		"DescribeHandshake", "DescribeOrganization", "DescribeOrganizationalUnit",
		"DescribePolicy", "DescribeResourcePolicy", "ListAccounts", "ListAccountsForParent",
		"ListAWSServiceAccessForOrganization", "ListChildren", "ListCreateAccountStatus",
		"ListDelegatedAdministrators", "ListDelegatedServicesForAccount",
		"ListEffectivePolicyValidationErrors", "ListHandshakesForAccount",
		"ListHandshakesForOrganization", "ListOrganizationalUnitsForParent", "ListParents",
		"ListPolicies", "ListPoliciesForTarget", "ListRoots", "ListTagsForResource",
		"ListTargetsForPolicy":
		return true
	default:
		return false
	}
}

var auditDocument = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"AccountName":                            {Mode: awsapi.IncludeField},
	"Email":                                  {Mode: awsapi.IncludeField},
	"CreateAccountStatus.AccountName":        {Mode: awsapi.IncludeField},
	"Notes":                                  {Mode: awsapi.IncludeField},
	"Target.Id":                              {Mode: awsapi.IncludeField},
	"Handshake.Parties.Id":                   {Mode: awsapi.IncludeField},
	"Handshake.Resources.Value":              {Mode: awsapi.IncludeField},
	"Handshake.Resources.Resources.Value":    {Mode: awsapi.IncludeField},
	"Content":                                {Mode: awsapi.JSONField},
	"Policy.Content":                         {Mode: awsapi.JSONField},
	"ResourcePolicy.Content":                 {Mode: awsapi.JSONField},
	"CreateAccountStatus.RequestedTimestamp": {TimeLayout: "Jan 2, 2006 3:04:05 PM"},
	"CreateAccountStatus.CompletedTimestamp": {TimeLayout: "Jan 2, 2006 3:04:05 PM"},
	"Handshake.RequestedTimestamp":           {TimeLayout: "Jan 2, 2006 3:04:05 PM"},
	"Handshake.ExpirationTimestamp":          {TimeLayout: "Jan 2, 2006 3:04:05 PM"},
}}

func auditOutcome(action string, input, output any, failure *awswire.Error) (journal.APICallCompleted, error) {
	model, _ := awscatalog.LookupService("organizations")
	op, ok := model.Operation(action)
	if !ok {
		return journal.APICallCompleted{}, awsapi.ErrUnknownOperation
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: readOnlyOperation(action), Request: auditDocument}
	// Response presence is independent of classification. Empty output operations
	// retain null, while asynchronous CreateAccount logs only its acceptance DTO,
	// never the later job result (which is a distinct AwsServiceEvent).
	switch action {
	case "AcceptHandshake", "CancelHandshake", "DeclineHandshake", "EnableAllFeatures",
		"InviteAccountToOrganization", "CreateAccount", "CreateOrganization",
		"CreateOrganizationalUnit", "UpdateOrganizationalUnit", "CreatePolicy",
		"UpdatePolicy", "EnablePolicyType", "DisablePolicyType", "PutResourcePolicy":
		projection.Response = &auditDocument
	}
	if projection.Response != nil && failure == nil {
		output = nativeHandshakeOutput(output)
	}
	call, err := projection.Call(model, op, input, output, failure)
	if err != nil {
		return call, err
	}
	if out, ok := output.(*api.DescribeOrganizationOutput); ok && failure == nil && out.Organization != nil {
		// LookupEvents.Resources is empty in the native capture, independently of
		// this actual CloudTrail document resource identity.
		call.EventResources = []journal.APIEventResource{{AccountID: inputString(out.Organization.MasterAccountId), Type: "AWS::Organizations::Organization", ARN: inputString(out.Organization.Arn)}}
	}
	return call, nil
}

func (s *Service) recordCall(ctx context.Context, call journal.APICallCompleted) error {
	m := awsctx.FromContext(ctx)
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: m.Partition, AccountID: m.AccountID, Region: "us-east-1"}, call)
}

func (s *Service) recordOutcome(ctx context.Context, action string, input, output any, failure *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	m := awsctx.FromContext(ctx)
	if m.Partition == "" || m.AccountID == "" {
		return nil
	}
	if _, ok := s.operations[action]; !ok {
		return nil
	}
	call, err := auditOutcome(action, input, output, failure)
	if err != nil {
		return err
	}
	return s.recordCall(ctx, call)
}

// RecordRequestError observes known, authenticated requests rejected before the
// command can run. Failed decoding never contributes raw request bytes.
func (s *Service) RecordRequestError(ctx context.Context, decoded awsapi.DecodedRequest, failure *awswire.Error) error {
	return s.recordOutcome(ctx, string(decoded.Operation.Name), decoded.Input, nil, failure)
}

func (s *Service) requestFailure(ctx context.Context, action string, input any, failure *awswire.Error) *awswire.Error {
	if err := s.recordOutcome(ctx, action, input, nil, failure); err != nil {
		return storageFailure()
	}
	return failure
}

// The documented CloudTrail handshake action is lower-case, unlike its API
// enum. Copy only the small enclosing DTO and handshake; keep the response sent
// to the caller and its resource collections untouched.
func nativeHandshakeOutput(output any) any {
	copyHandshake := func(handshake *api.Handshake) *api.Handshake {
		if handshake == nil || handshake.Action == nil {
			return handshake
		}
		out := *handshake
		out.Action = new(api.ActionType(strings.ToLower(string(*handshake.Action))))
		return &out
	}
	switch out := output.(type) {
	case *api.AcceptHandshakeOutput:
		copy := *out
		copy.Handshake = copyHandshake(out.Handshake)
		return &copy
	case *api.CancelHandshakeOutput:
		copy := *out
		copy.Handshake = copyHandshake(out.Handshake)
		return &copy
	case *api.DeclineHandshakeOutput:
		copy := *out
		copy.Handshake = copyHandshake(out.Handshake)
		return &copy
	case *api.EnableAllFeaturesOutput:
		copy := *out
		copy.Handshake = copyHandshake(out.Handshake)
		return &copy
	case *api.InviteAccountToOrganizationOutput:
		copy := *out
		copy.Handshake = copyHandshake(out.Handshake)
		return &copy
	default:
		return output
	}
}
