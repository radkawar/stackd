package s3

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"stackd/iam/policy"
)

// BucketPolicyAnonymousGrant proves an anonymous permission in the bucket's
// admitted policy, not its IsPublic classification or authorization of a request.
// False means no proof in the supported domain, not that the policy is private.
// The grant is independent of Block Public Access masks, object existence,
// ownership, encryption and other runtime requirements for a successful API call.
//
// The proof domain is universal-principal allows, unconditional or conditioned
// only on literal aws:SecureTransport, aws:PrincipalAccount and
// aws:PrincipalIsAWSService comparisons, for ListBucket,
// GetObject, GetObjectVersion and PutObject on this bucket and its object ARN
// language, with nonempty keys of at most 1024 UTF-8 bytes. These operations
// support anonymous callers; other IAM permissions alone do not prove that the
// corresponding S3 API accepts unsigned requests.
// Explicit denies are subtracted at the same action/resource, including unions,
// NotAction and NotResource. HTTP and HTTPS are separate consistent contexts.
// Anonymous PrincipalAccount is "anonymous"; PrincipalIsAWSService is absent.
// Other conditional denies are conservatively unconditional; the policy writer's
// request context is never used to establish a grant.
//
// References:
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-language-overview.html
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
func BucketPolicyAnonymousGrant(ctx context.Context, bucket BucketRecord) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if bucket.Policy.Document == "" {
		return false, nil
	}
	statements, compiled, err := parseS3PolicyStatements(bucket.Policy.Document)
	if errors.Is(err, policy.ErrUnsupported) {
		// TODO: Comeback extend supported principal/condition reasoning without
		// turning an incomplete evidence query into a source-policy rejection.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	transports := []string{"false"}
	for _, statement := range statements {
		if _, transport := anonymousPolicyConditionDomain(statement); transport {
			transports = append(transports, "true")
			break
		}
	}
	bucketARN := bucket.Key.ARN()
	// '?' requires a nonempty key; the remaining '*' is a language, not a
	// guessed representative object that could miss a denied prefix or suffix.
	objects := []string{bucketARN + "/?*"}
	resources := map[string][]string{
		"s3:ListBucket":       {bucketARN},
		"s3:GetObject":        objects,
		"s3:GetObjectVersion": objects,
		"s3:PutObject":        objects,
	}
	maxObjectBytes := len(bucketARN) + 1 + 1024
	limits := map[string]int{
		"s3:GetObject":        maxObjectBytes,
		"s3:GetObjectVersion": maxObjectBytes,
		"s3:PutObject":        maxObjectBytes,
	}
	for _, transport := range transports {
		request := policy.Request{Action: "s3:GetObject", Resource: bucketARN,
			Context: map[string][]string{
				"aws:SecureTransport":  {transport},
				"aws:PrincipalAccount": {policy.AnonymousAccountID},
			}}
		projection, err := anonymousPolicyProjection(statements, compiled, request)
		if err != nil {
			return false, err
		}
		if len(projection) == 0 {
			continue
		}
		summary, err := publicPolicySummary(projection)
		if err != nil {
			return false, err
		}
		actions, err := policy.PotentialActionsWithResourceLimits(ctx, [][]*policy.PermissionSummary{{summary}}, resources, limits)
		if err != nil || len(actions) != 0 {
			return len(actions) != 0, err
		}
	}
	return false, nil
}

func anonymousPolicyProjection(statements []publicPolicyStatement, compiled *policy.Document, request policy.Request) ([]publicPolicyStatement, error) {
	projection := make([]publicPolicyStatement, 0, len(statements))
	hasAllow := false
	for index, statement := range statements {
		anonymous := publicPolicyUniversalPrincipal(statement.Principal)
		if len(statement.NotPrincipal) != 0 {
			// Anonymous matches none of the admitted fixed identities.
			anonymous = !publicPolicyUniversalPrincipal(statement.NotPrincipal)
		}
		if !anonymous {
			continue
		}
		known, _ := anonymousPolicyConditionDomain(statement)
		if known && len(statement.Condition) != 0 {
			matches, err := compiled.ConditionsMatch(index, request)
			if err != nil {
				return nil, err
			}
			if !matches {
				continue
			}
		}
		variable := anonymousPolicyResourceVariable(statement)
		if statement.Effect == "Allow" {
			// TODO: Comeback prove other conditions, policy-variable values and
			// additional audiences/unsigned operations; not Zelkova equivalence.
			if !known || variable {
				continue
			}
			hasAllow = true
		} else if variable {
			// TODO: Comeback reason about variable-resource denies. Until then,
			// over-approximate their resources, preserving their action selector.
			statement.Resource, statement.NotResource = json.RawMessage(`"*"`), nil
		}
		// TODO: Comeback reason about other conditional denies. Unknown
		// conditions strengthen Deny; known conditions matched this same context.
		projection = append(projection, publicPolicySelectors(statement))
	}
	if !hasAllow {
		return nil, nil
	}
	return projection, nil
}

// The second result indicates whether a supported condition varies by transport.
// PrincipalIsAWSService is deliberately absent, not false, for unsigned callers.
func anonymousPolicyConditionDomain(statement publicPolicyStatement) (bool, bool) {
	transport := false
	for _, keys := range statement.Condition {
		for key, raw := range keys {
			switch {
			case strings.EqualFold(key, "aws:SecureTransport"):
				transport = true
			case strings.EqualFold(key, "aws:PrincipalAccount"),
				strings.EqualFold(key, "aws:PrincipalIsAWSService"):
			default:
				return false, false
			}
			for _, value := range policyStrings(raw) {
				if strings.Contains(value, "${") {
					return false, false
				}
			}
		}
	}
	return true, transport
}

func anonymousPolicyResourceVariable(statement publicPolicyStatement) bool {
	for _, resource := range policyStrings(statement.Resource) {
		if strings.Contains(resource, "${") {
			return true
		}
	}
	for _, resource := range policyStrings(statement.NotResource) {
		if strings.Contains(resource, "${") {
			return true
		}
	}
	return false
}
