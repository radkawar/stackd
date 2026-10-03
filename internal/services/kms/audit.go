package kms

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

var auditRequestProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"GrantTokens": {Mode: awsapi.OmitField}, "GrantToken": {Mode: awsapi.OmitField},
	"ValidTo": {TimeLayout: time.RFC3339},
}}

var auditResponseProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"KeyMetadata.CreationDate":        {TimeLayout: time.RFC3339},
	"KeyMetadata.DeletionDate":        {TimeLayout: time.RFC3339},
	"KeyMetadata.ValidTo":             {TimeLayout: time.RFC3339},
	"ReplicaKeyMetadata.CreationDate": {TimeLayout: time.RFC3339},
	"DeletionDate":                    {TimeLayout: time.RFC3339},
	"GrantToken":                      {Mode: awsapi.OmitField},
}}

// KMS cryptographic operations are Read management events, not data events.
// Native captures: testdata/aws/cloudtrail/service_management_events.json.
// Remaining operations follow the explicit operation examples in
// https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html.
func auditProjection(name string) (apievents.Projection, bool) {
	p := apievents.Projection{Category: journal.CategoryManagement, Request: auditRequestProjection}
	switch name {
	case "Encrypt", "Decrypt", "ReEncrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext",
		"GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext", "GenerateRandom", "GenerateMac", "VerifyMac",
		"Sign", "Verify", "DeriveSharedSecret", "GetPublicKey", "DescribeKey", "ListKeys", "ListAliases",
		"GetKeyPolicy", "ListKeyPolicies", "ListGrants", "ListRetirableGrants", "ListResourceTags",
		"GetKeyRotationStatus", "ListKeyRotations", "GetParametersForImport":
		p.ReadOnly = true
	case "CreateKey", "EnableKey", "DisableKey", "UpdateKeyDescription", "ScheduleKeyDeletion", "CancelKeyDeletion",
		"CreateAlias", "UpdateAlias", "DeleteAlias", "CreateGrant", "RevokeGrant", "RetireGrant",
		"PutKeyPolicy", "TagResource", "UntagResource", "EnableKeyRotation", "DisableKeyRotation", "RotateKeyOnDemand",
		"ImportKeyMaterial", "DeleteImportedKeyMaterial", "ReplicateKey", "UpdatePrimaryRegion":
		p.Response = &auditResponseProjection
	default:
		return p, false
	}
	return p, true
}

type auditContextKey struct{}
type auditContext struct {
	resources      []journal.APIEventResource
	retiredGrantID string
	regional       []regionalAudit
	roleRejection  interface{ RecordRejection(context.Context) error }
}

type regionalAudit struct {
	region, name  string
	input, output any
	resource      journal.APIEventResource
}

// Resource identity comes from actual source resolution, including failed
// authorizations. Never resolve a second time merely to decorate an audit entry.
func auditKey(ctx context.Context, k *key) {
	a, _ := ctx.Value(auditContextKey{}).(*auditContext)
	if a == nil {
		return
	}
	for _, r := range a.resources {
		if r.ARN == k.arn {
			return
		}
	}
	a.resources = append(a.resources, journal.APIEventResource{AccountID: keyScope(k).account, Type: "AWS::KMS::Key", ARN: k.arn})
}

// auditCommand owns the same native transaction as the command. Failures,
// including DryRun, are recorded only after rollback has completed.
func (s *Service) auditCommand(ctx context.Context, name string, input any, fn func(context.Context) (any, *awswire.Error)) (any, *awswire.Error) {
	ctx = withAction(ctx, name, nil)
	a := &auditContext{}
	ctx = context.WithValue(ctx, auditContextKey{}, a)
	var output any
	attemptContext, outcomes := apievents.RetainChildOutcomes(ctx)
	attemptErr := s.storage.Attempt(attemptContext, func(tx Transaction) error {
		if err := s.withWriteSet(tx, func(txctx context.Context) (bool, error) {
			var rejected *awswire.Error
			output, rejected = fn(txctx)
			if rejected != nil {
				return false, rejected
			}
			return true, nil
		}); err != nil {
			return err
		}
		// Consumers of committed API outcomes must see the new typed key/tag
		// rows. State and outcomes still share this command's native savepoint.
		txctx := tx.Context()
		if err := s.recordOutcome(txctx, name, input, output, nil, a); err != nil {
			return failure("KMSInternalException", "Unable to record KMS API outcome.")
		}
		for _, child := range a.regional {
			state := &auditContext{resources: []journal.APIEventResource{child.resource}}
			if err := s.recordOutcome(regionalContext(txctx, child.region), child.name, child.input, child.output, nil, state); err != nil {
				return failure("KMSInternalException", "Unable to record KMS API outcome.")
			}
		}
		return nil
	})
	err := transactionError(attemptErr)
	if err != nil {
		if a.roleRejection != nil {
			if recordErr := a.roleRejection.RecordRejection(ctx); recordErr != nil {
				return nil, failure("KMSInternalException", "Unable to record IAM service-role rejection.")
			}
		}
		if recordErr := s.recordOutcome(ctx, name, input, nil, err, a); recordErr != nil {
			return nil, failure("KMSInternalException", "Unable to record KMS API outcome.")
		}
		for _, child := range a.regional {
			state := &auditContext{resources: []journal.APIEventResource{child.resource}}
			if recordErr := s.recordOutcome(regionalContext(ctx, child.region), child.name, child.input, nil, err, state); recordErr != nil {
				return nil, failure("KMSInternalException", "Unable to record KMS API outcome.")
			}
		}
		return nil, err
	}
	outcomes.Accept()
	return output, nil
}

func (s *Service) recordOutcome(ctx context.Context, name string, input, output any, apiErr *awswire.Error, a *auditContext) error {
	if s.apiEvents == nil {
		return nil
	}
	p, known := auditProjection(name)
	if !known {
		return nil
	}
	metadata := awsctx.FromContext(ctx)
	serviceCall := metadata.ServicePrincipal.Name != ""
	via, _ := ctx.Value(viaServiceContextKey{}).(string)
	forwardedSNS := strings.HasPrefix(via, "sns.")
	forwardedEC2 := strings.HasPrefix(via, "ec2.") && (metadata.InvokedBy == "ec2-frontend-api.amazonaws.com" || strings.HasPrefix(metadata.InvokedBy, "prod.kms-caller.ebs."))
	if serviceCall {
		// SNS audit identity is producer-specific; CloudTrail retains its actor.
		// TODO: Comeback calibrate SNS producer failures beyond EventBridge's disabled-key calls.
		metadata.ServicePrincipal.Type = "AWSService"
		producer, _, _ := strings.Cut(metadata.ServicePrincipal.Name, ".")
		if forwardedSNS && (producer == "events" || producer == "cloudwatch" || producer == "s3") {
			// Authorization uses the producer; these SNS paths audit the forwarding service.
			metadata.ServicePrincipal.Name = metadata.CalledVia[len(metadata.CalledVia)-1]
			metadata.InvokedBy = metadata.ServicePrincipal.Name
		}
		if metadata.InvokedBy == "" {
			metadata.InvokedBy = metadata.ServicePrincipal.Name
		}
		// This metadata copy is audit-only. The EBS KMS caller is distinct
		// from the regional EC2 service principal that consumes the grant.
		metadata.ServicePrincipal.Name = metadata.InvokedBy
	} else if forwardedSNS {
		// TODO: Comeback calibrate provider-created forward-access credential/session audit fields.
		metadata.InvokedBy = metadata.CalledVia[len(metadata.CalledVia)-1]
	}
	if serviceCall || forwardedSNS {
		metadata.SourceIP, metadata.UserAgent = metadata.InvokedBy, metadata.InvokedBy
		ctx = awsctx.WithMetadata(ctx, metadata)
	}
	model, _ := awscatalog.LookupService("kms")
	op, _ := model.Operation(name)
	call, err := p.Call(model, op, input, output, apiErr)
	if err != nil {
		return err
	}
	var request map[string]any
	if len(call.RequestParameters) != 0 {
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
	}
	if request == nil && input != nil && name == "CreateKey" {
		request = make(map[string]any)
	}
	if request != nil {
		setDefault := func(field string, v any) {
			if _, ok := request[field]; !ok {
				request[field] = v
			}
		}
		switch name {
		case "Encrypt", "Decrypt":
			setDefault("encryptionAlgorithm", "SYMMETRIC_DEFAULT")
		case "ReEncrypt":
			setDefault("sourceEncryptionAlgorithm", "SYMMETRIC_DEFAULT")
			setDefault("destinationEncryptionAlgorithm", "SYMMETRIC_DEFAULT")
		case "Sign", "Verify":
			setDefault("messageType", "RAW")
		case "CreateKey":
			setDefault("keyUsage", "ENCRYPT_DECRYPT")
			setDefault("origin", "AWS_KMS")
			setDefault("bypassPolicyLockoutSafetyCheck", false)
			if spec, ok := request["customerMasterKeySpec"]; ok {
				setDefault("keySpec", spec)
			}
			setDefault("keySpec", "SYMMETRIC_DEFAULT")
			setDefault("customerMasterKeySpec", request["keySpec"])
		}
		if serviceCall && name == "GenerateDataKey" && apiErr != nil && apiErr.Code == "DisabledException" {
			delete(request, "encryptionContext")
		}
		call.RequestParameters, err = json.Marshal(request)
		if err != nil {
			return err
		}
	}
	if a != nil {
		call.EventResources = append(call.EventResources, a.resources...)
	}
	if name == "UpdatePrimaryRegion" && len(call.EventResources) > 1 {
		call.EventResources = call.EventResources[:1]
	}
	if result, ok := output.(*kmsapi.ReEncryptOutput); ok && apiErr == nil && len(call.EventResources) == 1 && result.KeyId != nil && result.SourceKeyId != nil && *result.KeyId == *result.SourceKeyId {
		// The two native resource entries represent source and destination
		// roles, even when both resolve to the same physical CMK.
		call.EventResources = append(call.EventResources, call.EventResources[0])
	}
	// ReEncrypt resolves the destination first but native resources list source first.
	if name == "ReEncrypt" && len(call.EventResources) == 2 {
		call.EventResources[0], call.EventResources[1] = call.EventResources[1], call.EventResources[0]
	}
	if apiErr != nil && apiErr.Code == "NotFoundException" && len(call.EventResources) == 0 {
		call.RequestParameters = nil
	}
	if apiErr != nil && (apiErr.Code == "InvalidCiphertextException" || apiErr.Code == "KMSInvalidSignatureException" || apiErr.Code == "KMSInvalidMacException" || name == "GetPublicKey" && apiErr.Code == "UnsupportedOperationException") {
		call.ErrorMessage = ""
	}
	if len(call.EventResources) != 0 {
		keyARN := call.EventResources[len(call.EventResources)-1].ARN
		if name == "Decrypt" && apiErr == nil && !serviceCall && strings.HasPrefix(via, "ec2.") && metadata.InvokedBy == "ebs.amazonaws.com" {
			// Direct EBS reads name the resolved CMK; grant-backed service
			// decryption during volume creation deliberately omits this field.
			request["keyId"] = keyARN
			call.RequestParameters, err = json.Marshal(request)
			if err != nil {
				return err
			}
		}
		injectKeyARN := false
		switch name {
		case "CreateAlias", "UpdateAlias", "DeleteAlias", "CreateGrant", "RevokeGrant",
			"DisableKey", "EnableKey", "EnableKeyRotation", "ImportKeyMaterial", "DeleteImportedKeyMaterial",
			"TagResource", "UntagResource", "UpdatePrimaryRegion", "ScheduleKeyDeletion", "CancelKeyDeletion":
			injectKeyARN = true
		case "RetireGrant":
			injectKeyARN = serviceCall && metadata.InvokedBy == "AWS Internal"
		}
		if apiErr == nil && injectKeyARN {
			var response map[string]any
			if len(call.ResponseElements) != 0 {
				if err := json.Unmarshal(call.ResponseElements, &response); err != nil {
					return err
				}
			}
			if response == nil {
				response = make(map[string]any)
			}
			response["keyId"] = keyARN
			call.ResponseElements, err = json.Marshal(response)
			if err != nil {
				return err
			}
		}
		lookupKeys := call.EventResources
		if alias, ok := request["aliasName"].(string); ok && apiErr == nil {
			// Native alias resources deliberately carry AWS::KMS::Key, not Alias.
			sc := scopeFor(ctx)
			call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: sc.account, Type: "AWS::KMS::Key", ARN: sc.arn(alias)})
		}
		if !p.ReadOnly {
			for _, r := range lookupKeys {
				call.Resources = append(call.Resources, journal.APIResource{Type: "AWS::KMS::Key", Name: strings.TrimPrefix(strings.SplitN(r.ARN, ":", 6)[5], "key/")})
				if apiErr == nil {
					call.Resources = append(call.Resources, journal.APIResource{Type: "AWS::KMS::Key", Name: r.ARN})
				}
			}
		} else {
			for _, field := range []string{"sourceKeyId", "destinationKeyId", "keyId"} {
				if id, ok := request[field].(string); ok {
					typ := ""
					if name == "GetPublicKey" {
						typ = "AWS::KMS::Key"
					}
					call.Resources = append(call.Resources, journal.APIResource{Type: typ, Name: id})
				}
			}
		}
	}
	if name == "RetireGrant" && a != nil && a.retiredGrantID != "" {
		call.AdditionalEventData, err = json.Marshal(map[string]string{"grantId": a.retiredGrantID})
		if err != nil {
			return err
		}
	}
	if name == "RetireGrant" && serviceCall && metadata.InvokedBy == "AWS Internal" {
		call.RequestParameters = nil
	}
	if name == "RotateKeyOnDemand" && apiErr == nil {
		call.ResponseElements, err = json.Marshal(map[string]any{"keyId": request["keyId"]})
		if err != nil {
			return err
		}
	}
	// Captured S3, SNS and EC2 copy forward-access denials omit key/context
	// parameters and resources. The public API remains AccessDeniedException.
	if apiErr != nil && apiErr.Code == "AccessDeniedException" {
		if strings.HasPrefix(via, "s3.") || forwardedSNS || forwardedEC2 {
			call.RequestParameters, call.EventResources, call.Resources = nil, nil, nil
			call.ErrorCode = "AccessDenied"
		}
	}
	sc := scopeFor(ctx)
	envelope := journal.Envelope{Partition: sc.partition, AccountID: sc.account, Region: sc.region, At: s.now()}
	var owners []string
	if apiErr == nil {
		for _, resource := range call.EventResources {
			if resource.AccountID == "" || resource.AccountID == sc.account {
				continue
			}
			duplicate := false
			for _, owner := range owners {
				if owner == resource.AccountID {
					duplicate = true
					break
				}
			}
			if !duplicate {
				owners = append(owners, resource.AccountID)
			}
		}
	}
	// Native KMS cross-account successes appear in caller and key-owner
	// histories with a shared ID. Access denials remain in caller history only.
	if len(owners) != 0 {
		call.SharedEventID = uuid.NewString()
	}
	if err := apievents.RecordRetained(ctx, s.apiEvents, envelope, call); err != nil {
		return err
	}
	for _, owner := range owners {
		envelope.AccountID = owner
		if err := apievents.RecordRetained(ctx, s.apiEvents, envelope, call); err != nil {
			return err
		}
	}
	return nil
}

// RecordRequestError captures only known, implemented KMS operations. Failed
// decoding has no generated input: raw rejected request bodies are never logged.
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, apiErr *awswire.Error) error {
	name := string(request.Operation.Name)
	if _, known := s.operations[name]; !known {
		return nil
	}
	return s.recordOutcome(ctx, name, request.Input, nil, apiErr, nil)
}

func (s *Service) requestError(ctx context.Context, name string, apiErr *awswire.Error) *awswire.Error {
	model, _ := awscatalog.LookupService("kms")
	op, _ := model.Operation(name)
	if err := s.RecordRequestError(ctx, awsapi.DecodedRequest{Operation: op}, apiErr); err != nil {
		return failure("KMSInternalException", "Unable to record KMS API outcome.")
	}
	return apiErr
}
