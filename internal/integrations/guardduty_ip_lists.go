package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	gdapi "stackd/internal/awsapi/guardduty"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/guardduty"
	"stackd/internal/services/iam"
)

// GuardDutyIPLists joins caller-authorized policy maintenance to service-role
// S3 reads. Read must run outside the GuardDuty write transaction: IAM session
// issuance and S3/KMS authorization own their own current transactions.
type GuardDutyIPLists struct {
	IAM interface {
		PutServiceLinkedRolePolicy(context.Context, iam.Scope, string, string, string, string) error
		DeleteServiceLinkedRolePolicy(context.Context, iam.Scope, string, string, string) error
	}
	Roles      ServiceRoles
	S3         LambdaS3Commands
	Authorizer authorization.Authorizer
}

func guardDutyListRole(list guardduty.IPList) string {
	return "arn:" + list.Partition + ":iam::" + list.AccountID + ":role/aws-service-role/" + guardduty.ServicePrincipal + "/" + guardduty.ServiceRoleName
}

func guardDutyListPolicyName(list guardduty.IPList) string {
	// Reserved implementation name, not a claim about native policy grouping.
	digest := sha256.Sum256([]byte(list.ARN))
	return "AWSServiceOwned-" + guardduty.ServicePrincipal + "-" + hex.EncodeToString(digest[:])
}

// IAM's predefined literal variables escape object-key wildcard/variable bytes
// without granting any neighboring key. Replace performs one pass.
var guardDutyListResourceEscapes = strings.NewReplacer("$", "${$}", "*", "${*}", "?", "${?}")

func (a GuardDutyIPLists) PutPolicy(ctx context.Context, list guardduty.IPList) error {
	bucket, key, err := guardDutyListLocation(list.Location)
	if err != nil {
		return err
	}
	if a.IAM == nil || a.Authorizer == nil {
		return errors.New("GuardDuty IP list IAM authority is unavailable")
	}
	if denied := a.Authorizer.Authorize(ctx, authorization.Request{Action: "iam:PutRolePolicy", ResourceARN: guardDutyListRole(list)}); denied != nil {
		return denied
	}
	resource, _ := json.Marshal("arn:" + list.Partition + ":s3:::" + bucket + "/" + guardDutyListResourceEscapes.Replace(key))
	document := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":` + string(resource) + `}]}`
	ctx = awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: guardduty.ServicePrincipal, Type: "AWSService"})
	return a.IAM.PutServiceLinkedRolePolicy(ctx, iam.Scope{Partition: list.Partition, AccountID: list.AccountID}, guardduty.ServicePrincipal, guardduty.ServiceRoleName, guardDutyListPolicyName(list), document)
}

func (a GuardDutyIPLists) DeletePolicy(ctx context.Context, list guardduty.IPList) error {
	if a.IAM == nil || a.Authorizer == nil {
		return errors.New("GuardDuty IP list IAM authority is unavailable")
	}
	request, _ := awsapi.FromContext(ctx)
	_, detectorCleanup := request.Input.(*gdapi.DeleteDetectorInput)
	// Detector deletion is an already-authorized service lifecycle, not the
	// public list-delete command requiring the caller's DeleteRolePolicy right.
	if !detectorCleanup {
		if denied := a.Authorizer.Authorize(ctx, authorization.Request{Action: "iam:DeleteRolePolicy", ResourceARN: guardDutyListRole(list)}); denied != nil {
			return denied
		}
	}
	ctx = awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: guardduty.ServicePrincipal, Type: "AWSService"})
	return a.IAM.DeleteServiceLinkedRolePolicy(ctx, iam.Scope{Partition: list.Partition, AccountID: list.AccountID}, guardduty.ServicePrincipal, guardduty.ServiceRoleName, guardDutyListPolicyName(list))
}

const guardDutyListMaxBytes = 35 << 20

func (a GuardDutyIPLists) Read(ctx context.Context, list guardduty.IPList) ([]byte, error) {
	bucket, key, err := guardDutyListLocation(list.Location)
	if err != nil {
		return nil, err
	}
	if a.S3 == nil {
		return nil, errors.New("GuardDuty IP list S3 reader is unavailable")
	}
	credential, wire := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: guardduty.ServicePrincipal, Type: "AWSService"}, guardDutyListRole(list), identity.RoleSessionSpec{SessionName: "GuardDutyIPList"}, "")
	if wire != nil {
		return nil, guardDutyListReadFailure()
	}
	ctx, wire = serviceRoleRequestContext(ctx, credential, list.Region, guardduty.ServicePrincipal)
	if wire != nil {
		return nil, guardDutyListReadFailure()
	}
	input := &s3api.GetObjectInput{Bucket: new(s3api.BucketName(bucket)), Key: new(s3api.ObjectKey(key))}
	head, wire := a.S3.HeadObject(ctx, (*s3api.HeadObjectInput)(input))
	if wire != nil {
		return nil, guardDutyListReadFailure()
	}
	if list.ExpectedBucketOwner != "" {
		if head.BucketAccountID != list.ExpectedBucketOwner {
			return nil, &awswire.Error{Code: "BadRequestException", Message: "The request failed because the expected bucket owner doesn't match the actual S3 bucket owner. Verify the account ID and bucket ownership, and then retry.", StatusCode: 400}
		}
		input.ExpectedBucketOwner = new(s3api.AccountId(list.ExpectedBucketOwner))
	}
	if head.Output.ContentLength == nil || *head.Output.ContentLength < 0 || *head.Output.ContentLength > guardDutyListMaxBytes || head.Output.SSECustomerAlgorithm != nil {
		return nil, guardDutyListReadFailure()
	}
	if head.Output.VersionId != nil && *head.Output.VersionId != "null" && *head.Output.VersionId != "" {
		input.VersionId = head.Output.VersionId
	} else if head.Output.ETag != nil && *head.Output.ETag != "" {
		input.IfMatch = new(s3api.IfMatch(*head.Output.ETag))
	} else {
		return nil, guardDutyListReadFailure()
	}
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID = uuid.NewString()
	ctx = awsctx.WithMetadata(ctx, metadata)
	out, wire := a.S3.GetObject(ctx, input)
	if wire != nil || len(out.Output.Body) > guardDutyListMaxBytes || out.Output.SSECustomerAlgorithm != nil {
		return nil, guardDutyListReadFailure()
	}
	return out.Output.Body, nil
}

func guardDutyListReadFailure() *awswire.Error {
	// The retained native fixture returns this service error with HTTP 400.
	return &awswire.Error{Code: "InternalServerErrorException", Message: "The request is rejected because the caller is not authorized to call this API.", StatusCode: 400}
}

var guardDutyS3Endpoint = regexp.MustCompile(`^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:\.cn)?$`)
var guardDutyS3Bucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// Accept S3 URI, virtual-hosted and path-style regional URLs, never an ambient
// HTTP fetch. Escaped keys are decoded exactly once; '+' remains a literal '+'.
func guardDutyListLocation(location string) (string, string, error) {
	bad := func() (string, string, error) {
		return "", "", &awswire.Error{Code: "BadRequestException", Message: "The request is rejected because the parameter ipSetLocation has an invalid value.", StatusCode: 400}
	}
	u, err := url.Parse(location)
	if err != nil || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return bad()
	}
	bucket, key := "", strings.TrimPrefix(u.Path, "/")
	host := strings.ToLower(u.Hostname())
	switch u.Scheme {
	case "s3":
		bucket = host
	case "https", "http":
		if guardDutyS3Endpoint.MatchString(host) {
			bucket, key, _ = strings.Cut(key, "/")
		} else if index := strings.LastIndex(host, ".s3"); index > 0 && guardDutyS3Endpoint.MatchString(host[index+1:]) {
			bucket = host[:index]
		} else {
			return bad()
		}
	default:
		return bad()
	}
	if !guardDutyS3Bucket.MatchString(bucket) || key == "" {
		return bad()
	}
	return bucket, key, nil
}
