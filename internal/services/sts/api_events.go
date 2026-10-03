package sts

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Native captures: testdata/aws/cloudtrail/service_management_events.json.
// Federation and cross-account projections follow IAM's CloudTrail integration
// examples. Token-size/utilization diagnostics have no local equivalent.
var stsAuditResponse = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Credentials.SecretAccessKey": {Mode: awsapi.OmitField},
	// Native STS logs sessionToken. Omitting it is an intentional credential-
	// safety divergence, not an assertion about AWS's redaction behavior.
	"Credentials.SessionToken": {Mode: awsapi.OmitField},
	"Credentials.Expiration":   {TimeLayout: time.RFC3339},
	"WebIdentityToken":         {Mode: awsapi.OmitField},
	"Expiration":               {TimeLayout: time.RFC3339},
}}

var stsAuditRequest = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"TokenCode":                         {Mode: awsapi.OmitField},
	"SAMLAssertion":                     {Mode: awsapi.OmitField},
	"WebIdentityToken":                  {Mode: awsapi.OmitField},
	"ProvidedContexts.ContextAssertion": {Mode: awsapi.OmitField},
}}

func stsAuditProjection(action string) (apievents.Projection, bool) {
	p := apievents.Projection{Category: journal.CategoryManagement, Request: stsAuditRequest}
	switch action {
	case "AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity":
		p.ReadOnly, p.Response = true, &stsAuditResponse
	case "AssumeRoot", "GetFederationToken", "GetSessionToken", "GetWebIdentityToken":
		p.Response = &stsAuditResponse
	case "GetCallerIdentity", "GetAccessKeyInfo":
		p.ReadOnly = true
	default:
		return p, false
	}
	return p, true
}

type federationAuditKey struct{}

// Only verified public claims enter this context; never the assertion or JWT.
type federationAudit struct {
	Identity                                 journal.APIIdentity
	AssertionID, SessionName, SourceIdentity string
	Tags                                     map[string]string
	TransitiveTagKeys                        []string
}

func (s *Service) appendAPICall(ctx context.Context, instant time.Time, action string, output any, failure *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	projection, ok := stsAuditProjection(action)
	if !ok {
		return nil
	}
	model, _ := awscatalog.LookupService("sts")
	operation, _ := model.Operation(action)
	var input any
	if decoded, ok := awsapi.FromContext(ctx); ok && decoded.Operation.Name == operation.Name {
		input = decoded.Input
	}
	call, err := projection.Call(model, operation, input, output, failure)
	if err != nil {
		return err
	}
	// Captured GetWebIdentityToken authorization denials omit parameters;
	// later disabled-federation and duration failures retain them.
	if action == "GetWebIdentityToken" && failure != nil && failure.Code == "AccessDenied" {
		call.RequestParameters = nil
	}
	m := awsctx.FromContext(ctx)
	if action == "AssumeRole" && len(call.RequestParameters) != 0 && (m.SourceIdentity != "" || len(m.TransitiveTagKeys) != 0) {
		var request map[string]any
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
		if request != nil {
			if request["sourceIdentity"] == nil && m.SourceIdentity != "" {
				request["sourceIdentity"] = m.SourceIdentity
			}
			var inherited map[string]string
			for _, key := range m.TransitiveTagKeys {
				if value, ok := findTag(m.SessionTags, key); ok {
					if inherited == nil {
						inherited = make(map[string]string, len(m.TransitiveTagKeys))
					}
					inherited[key] = value
				}
			}
			if len(inherited) != 0 {
				request["incomingTransitiveTags"] = inherited
			}
			call.RequestParameters, err = json.Marshal(request)
			if err != nil {
				return err
			}
		}
	}
	scope := journal.Envelope{At: instant, Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}
	if global, known := ctx.Value(globalEndpointKey{}).(bool); known {
		endpoint := "regional"
		if global {
			endpoint = "global"
			// Global endpoint history is stored in us-east-1, independently
			// of the region that actually served the request.
			scope.Region = "us-east-1"
		}
		call.AdditionalEventData, err = json.Marshal(map[string]any{"RequestDetails": map[string]string{"endpointType": endpoint, "awsServingRegion": m.Region}})
		if err != nil {
			return err
		}
	}
	var roleARN, providerARN, target string
	switch in := input.(type) {
	case *stsapi.AssumeRoleInput:
		if in != nil {
			roleARN = value(in.RoleArn)
		}
	case *stsapi.AssumeRoleWithSAMLInput:
		if in != nil {
			roleARN, providerARN = value(in.RoleArn), value(in.PrincipalArn)
		}
	case *stsapi.AssumeRoleWithWebIdentityInput:
		if in != nil {
			roleARN = value(in.RoleArn)
		}
	case *stsapi.AssumeRootInput:
		if in != nil {
			target = value(in.TargetPrincipal)
			if parsed, err := arn.Parse(target); err == nil {
				target = parsed.AccountID
			}
		}
	}
	if parsed, err := arn.Parse(roleARN); err == nil && parsed.Service == "iam" && strings.HasPrefix(parsed.Resource, "role/") {
		target = parsed.AccountID
		if failure == nil {
			call.EventResources = []journal.APIEventResource{{AccountID: target, Type: "AWS::IAM::Role", ARN: roleARN}}
			if providerARN != "" {
				call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: target, Type: "AWS::IAM::SAMLProvider", ARN: providerARN})
			}
			if m.ServicePrincipal.Name != "" {
				// The AWS service is the caller; the triggering resource's
				// account is not a second customer recipient.
				scope.AccountID = target
				call.SharedEventID = uuid.NewString()
			}
		}
	}
	if action == "AssumeRoleWithSAML" || action == "AssumeRoleWithWebIdentity" {
		if target != "" {
			scope.AccountID = target
		}
		call.Identity.Type = "WebIdentityUser"
		if action == "AssumeRoleWithSAML" {
			call.Identity.Type = "SAMLUser"
		}
		if verified, ok := ctx.Value(federationAuditKey{}).(federationAudit); ok {
			call.Identity = verified.Identity
			var request map[string]any
			if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
				return err
			}
			if request == nil {
				request = make(map[string]any)
			}
			if verified.AssertionID != "" {
				request["sAMLAssertionID"] = verified.AssertionID
			}
			if verified.SessionName != "" {
				request["roleSessionName"] = verified.SessionName
			}
			if verified.SourceIdentity != "" {
				request["sourceIdentity"] = verified.SourceIdentity
			}
			if len(verified.Tags) != 0 {
				request["principalTags"] = verified.Tags
			}
			if len(verified.TransitiveTagKeys) != 0 {
				request["transitiveTagKeys"] = verified.TransitiveTagKeys
			}
			call.RequestParameters, err = json.Marshal(request)
			if err != nil {
				return err
			}
		}
	}
	stsAuditLookupResources(&call, roleARN, output)
	// Denials belong only to the caller's account. Successful cross-account
	// assumptions publish both records in the credential authority transaction.
	crossAccount := failure == nil && target != "" && target != scope.AccountID && (action == "AssumeRole" || action == "AssumeRoot")
	if crossAccount {
		call.SharedEventID = uuid.NewString()
	}
	if failure != nil {
		return apievents.RecordRetained(ctx, s.apiEvents, scope, call)
	}
	if err := s.apiEvents.Record(ctx, scope, call); err != nil {
		return err
	}
	if crossAccount {
		scope.AccountID = target
		call.EventID = ""
		call.Identity = journal.APIIdentity{Type: "AWSAccount", AccountID: m.AccountID, PrincipalID: m.PrincipalID}
		m.PrincipalARN = ""
		return s.apiEvents.Record(awsctx.WithMetadata(ctx, m), scope, call)
	}
	return nil
}

func stsAuditLookupResources(call *journal.APICallCompleted, roleARN string, output any) {
	var credentials *stsapi.Credentials
	var assumed *stsapi.AssumedRoleUser
	var federated *stsapi.FederatedUser
	switch out := output.(type) {
	case *stsapi.AssumeRoleOutput:
		if out != nil {
			credentials, assumed = out.Credentials, out.AssumedRoleUser
		}
	case *stsapi.AssumeRoleWithSAMLOutput:
		if out != nil {
			credentials, assumed = out.Credentials, out.AssumedRoleUser
		}
	case *stsapi.AssumeRoleWithWebIdentityOutput:
		if out != nil {
			credentials, assumed = out.Credentials, out.AssumedRoleUser
		}
	case *stsapi.GetFederationTokenOutput:
		if out != nil {
			credentials, federated = out.Credentials, out.FederatedUser
		}
	case *stsapi.GetSessionTokenOutput:
		if out != nil {
			credentials = out.Credentials
		}
	case *stsapi.AssumeRootOutput:
		if out != nil {
			credentials = out.Credentials
		}
	}
	if credentials != nil {
		call.Resources = append(call.Resources, journal.APIResource{Type: "AWS::IAM::AccessKey", Name: value(credentials.AccessKeyId)})
	}
	if assumed != nil {
		sessionARN := value(assumed.Arn)
		call.Resources = append(call.Resources, journal.APIResource{Type: "AWS::STS::AssumedRole", Name: sessionARN}, journal.APIResource{Type: "AWS::STS::AssumedRole", Name: value(assumed.AssumedRoleId)}, journal.APIResource{Type: "AWS::STS::AssumedRole", Name: sessionARN[strings.LastIndex(sessionARN, "/")+1:]}, journal.APIResource{Type: "AWS::IAM::Role", Name: roleARN})
	}
	if federated != nil {
		userARN := value(federated.Arn)
		call.Resources = append(call.Resources, journal.APIResource{Type: "AWS::STS::FederatedUser", Name: value(federated.FederatedUserId)}, journal.APIResource{Type: "AWS::STS::FederatedUser", Name: userARN}, journal.APIResource{Type: "AWS::STS::FederatedUser", Name: userARN[strings.LastIndex(userARN, "/")+1:]})
	}
}

// RecordRequestError records known authenticated decode and credential rejections
// after the caller's failed/read transaction has closed. No raw request is used.
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, failure *awswire.Error) error {
	return s.appendAPICall(awsapi.WithDecodedRequest(ctx, request), s.now(), string(request.Operation.Name), nil, failure)
}

// RecordAssumeRole records successful service-role issuance in its existing IAM
// authority transaction. Denied service assumptions have no customer-account
// record, just as other denied cross-account STS assumptions omit the recipient.
func (s *Service) RecordAssumeRole(ctx context.Context, instant time.Time, input *stsapi.AssumeRoleInput, output *stsapi.AssumeRoleOutput) error {
	model, _ := awscatalog.LookupService("sts")
	operation, _ := model.Operation("AssumeRole")
	ctx = awsapi.WithDecodedRequest(ctx, awsapi.DecodedRequest{Operation: operation, Input: input})
	return s.appendAPICall(ctx, instant, "AssumeRole", output, nil)
}

func stsAuditFailure() *awswire.Error {
	return &awswire.Error{Code: "InternalFailure", Message: "Unable to record STS API outcome.", StatusCode: 500}
}

func webIdentityAudit(provider, audience, subject string) journal.APIIdentity {
	return journal.APIIdentity{Type: "WebIdentityUser", PrincipalID: provider + ":" + audience + ":" + subject, UserName: subject, IdentityProvider: provider}
}

func samlIdentityAudit(qualifier, subject string) journal.APIIdentity {
	return journal.APIIdentity{Type: "SAMLUser", PrincipalID: qualifier + ":" + subject, UserName: subject, IdentityProvider: qualifier}
}
