package kms

import (
	"context"
	"fmt"

	"stackd/internal/authorization"
	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func defaultPolicy(ctx context.Context) string {
	sc := scopeFor(ctx)
	return fmt.Sprintf(`{"Version":"2012-10-17","Id":"key-default-1","Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow","Principal":{"AWS":"arn:%s:iam::%s:root"},"Action":"kms:*","Resource":"*"}]}`, sc.partition, sc.account)
}

func servicePolicy(ctx context.Context, service string) string {
	sc := scopeFor(ctx)
	if service == "s3" {
		return fmt.Sprintf(`{"Version":"2012-10-17","Id":"auto-s3-2","Statement":[{"Sid":"Allow access through S3 for all principals in the account that are authorized to use S3","Effect":"Allow","Principal":{"AWS":"*"},"Action":["kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:DescribeKey"],"Resource":"*","Condition":{"StringEquals":{"kms:ViaService":"s3.%s.amazonaws.com","kms:CallerAccount":"%s"}}},{"Sid":"Allow direct access to key metadata to the account","Effect":"Allow","Principal":{"AWS":"arn:%s:iam::%s:root"},"Action":["kms:Describe*","kms:Get*","kms:List*"],"Resource":"*"}]}`, sc.region, sc.account, sc.partition, sc.account)
	}
	// EBS's managed key remains alias/aws/ebs, while snapshot requests use the
	// EC2 forwarding condition rather than their ebs.amazonaws.com audit origin.
	if service == "ebs" {
		service = "ec2"
	}
	// SQS's native policy in rotation.json permits account metadata reads and
	// service-mediated grant creation as well as crypto.
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"Allow use through the service","Effect":"Allow","Principal":{"AWS":"*"},"Action":["kms:Encrypt","kms:Decrypt","kms:ReEncrypt*","kms:GenerateDataKey*","kms:CreateGrant","kms:DescribeKey"],"Resource":"*","Condition":{"StringEquals":{"kms:CallerAccount":"%s","kms:ViaService":"%s.%s.amazonaws.com"}}},{"Sid":"Allow account metadata access","Effect":"Allow","Principal":{"AWS":"arn:%s:iam::%s:root"},"Action":["kms:Describe*","kms:Get*","kms:List*","kms:RevokeGrant"],"Resource":"*"}]}`, sc.account, service, sc.region, sc.partition, sc.account)
}

func (s *Service) registerPolicies() {
	register(s, "GetKeyPolicy", s.getKeyPolicy)
	register(s, "PutKeyPolicy", s.putKeyPolicy)
	register(s, "ListKeyPolicies", s.listKeyPolicies)
}

func policyName(name *kmsapi.PolicyNameType) *awswire.Error {
	if name != nil && value(name) != "default" {
		return failure("NotFoundException", "The only valid key policy name is default.")
	}
	return nil
}

// creationPolicy supplies the service-owned default without a caller lockout
// check. Native CreateKey succeeds with only kms:CreateKey when Policy is
// omitted; caller-supplied policies still receive the safety check.
func (s *Service) creationPolicy(ctx context.Context, policy *kmsapi.PolicyType, arn string, bypass bool) (authorization.BoundPolicy, *awswire.Error) {
	if policy == nil {
		return authorization.BoundPolicy{Document: defaultPolicy(ctx)}, nil
	}
	return s.validateKeyPolicy(ctx, value(policy), arn, bypass)
}

func (s *Service) validateKeyPolicy(ctx context.Context, document, arn string, bypass bool) (authorization.BoundPolicy, *awswire.Error) {
	bound := authorization.BoundPolicy{Document: document}
	if err := authorization.ValidateResourcePolicy([]byte(document)); err != nil {
		return bound, failure("MalformedPolicyDocumentException", err.Error())
	}
	if binder, ok := s.authorizer.(authorization.PolicyBinder); ok {
		var err error
		bound, err = binder.BindResourcePolicy(ctx, document, authorization.ResourcePolicyOptions{})
		if err != nil {
			return bound, failure("MalformedPolicyDocumentException", err.Error())
		}
	}
	if !bypass {
		if err := s.authorizeBound(withAction(ctx, "PutKeyPolicy", nil), arn, bound, true, nil); err != nil {
			return bound, failure("MalformedPolicyDocumentException", "The new key policy will not allow you to update the key policy in the future.")
		}
	}
	return bound, nil
}

func (s *Service) getKeyPolicy(ctx context.Context, in *kmsapi.GetKeyPolicyInput) (*kmsapi.GetKeyPolicyOutput, *awswire.Error) {
	if err := policyName(in.PolicyName); err != nil {
		return nil, err
	}
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	document := k.policy
	if binder, ok := s.authorizer.(authorization.PolicyBinder); ok {
		var err error
		document, err = binder.RenderResourcePolicy(ctx, authorization.BoundPolicy{Document: k.policy, PrincipalIDs: k.principalIDs})
		if err != nil {
			return nil, failure("KMSInternalException", "Unable to render key policy principals.")
		}
	}
	return &kmsapi.GetKeyPolicyOutput{Policy: ptr(kmsapi.PolicyType(document)), PolicyName: ptr(kmsapi.PolicyNameType("default"))}, nil
}

func (s *Service) putKeyPolicy(ctx context.Context, in *kmsapi.PutKeyPolicyInput) (*kmsapi.PutKeyPolicyOutput, *awswire.Error) {
	if err := policyName(in.PolicyName); err != nil {
		return nil, err
	}
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	if err := customerKey(k); err != nil {
		return nil, err
	}
	bound, err := s.validateKeyPolicy(ctx, value(in.Policy), k.arn, isTrue(in.BypassPolicyLockoutSafetyCheck))
	if err != nil {
		return nil, err
	}
	k.policy, k.principalIDs = bound.Document, bound.PrincipalIDs
	return &kmsapi.PutKeyPolicyOutput{}, nil
}

func (s *Service) listKeyPolicies(ctx context.Context, in *kmsapi.ListKeyPoliciesInput) (*kmsapi.ListKeyPoliciesOutput, *awswire.Error) {
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), false)
	if err != nil {
		return nil, err
	}
	page, next, err := s.page(ctx, "ListKeyPolicies", k.ID, []string{"default"}, in.Limit, in.Marker)
	if err != nil {
		return nil, err
	}
	out := &kmsapi.ListKeyPoliciesOutput{PolicyNames: make(kmsapi.PolicyNameList, 0, len(page)), Truncated: ptr(kmsapi.BooleanType(next != ""))}
	for _, name := range page {
		out.PolicyNames = append(out.PolicyNames, kmsapi.PolicyNameType(name))
	}
	if next != "" {
		out.NextMarker = ptr(kmsapi.MarkerType(next))
	}
	return out, nil
}
