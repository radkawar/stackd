package sts

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"stackd/iam/policy"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func (s *Service) sessionPolicies(ctx context.Context, accountID, inline string, descriptors stsapi.PolicyDescriptorListType) ([]string, *awswire.Error) {
	if len(descriptors) > 10 {
		return nil, stsValidation("At most 10 managed session policies may be supplied.")
	}
	size := utf8.RuneCountInString(inline)
	var documents, arns []string
	if inline != "" {
		if _, err := policy.ParseSession([]byte(inline)); err != nil {
			return nil, &awswire.Error{Code: "MalformedPolicyDocument", Message: err.Error(), StatusCode: 400}
		}
		documents = append(documents, inline)
	}
	m := awsctx.FromContext(ctx)
	for _, descriptor := range descriptors {
		arn := value(descriptor.Arn)
		parts := strings.SplitN(arn, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] != m.Partition || parts[2] != "iam" || parts[3] != "" || (parts[4] != accountID && parts[4] != "aws") || !strings.HasPrefix(parts[5], "policy/") {
			return nil, stsValidation("Managed session policies must belong to the session's account and partition.")
		}
		size += utf8.RuneCountInString(arn)
		arns = append(arns, arn)
	}
	if size > 2048 {
		return nil, stsValidation("The combined session policy and policy ARN text exceeds 2048 characters.")
	}
	if len(arns) > 0 {
		if s.roles == nil {
			return nil, stsDenied("IAM session policy source is unavailable.")
		}
		m.AccountID = accountID
		_, err := s.roles.ResolveManagedPolicyDocuments(awsctx.WithMetadata(ctx, m), arns)
		if err != nil {
			return nil, &awswire.Error{Code: "MalformedPolicyDocument", Message: "A managed session policy could not be resolved.", StatusCode: 400}
		}
	}
	return documents, nil
}

// Managed session policy references remain live for the life of the session.
// Inline session documents are fixed by the credential issuance request.
func sessionPolicyARNs(descriptors stsapi.PolicyDescriptorListType) []string {
	arns := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		arns = append(arns, value(descriptor.Arn))
	}
	return arns
}

func sessionTags(tags stsapi.TagListType) (map[string]string, *awswire.Error) {
	if len(tags) > 50 {
		return nil, stsValidation("At most 50 session tags may be supplied.")
	}
	result := make(map[string]string, len(tags))
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		key, val := value(tag.Key), value(tag.Value)
		canonical := strings.ToLower(key)
		if seen[canonical] || strings.HasPrefix(canonical, "aws:") {
			return nil, stsValidation("Session tag keys must be unique ignoring case and cannot begin with aws:.")
		}
		seen[canonical] = true
		result[key] = val
	}
	return result, nil
}

// AWS keeps its packing format private. This local compression budget gives
// bounded tokens and a meaningful size response rather than a constant success.
func packedSize(inline string, arns stsapi.PolicyDescriptorListType, tags map[string]string) (int32, *awswire.Error) {
	if inline == "" && len(arns) == 0 && len(tags) == 0 {
		return 0, nil
	}
	payload, err := json.Marshal(struct {
		Policy string
		ARNs   stsapi.PolicyDescriptorListType
		Tags   map[string]string
	}{inline, arns, tags})
	if err != nil {
		return 0, stsValidation("Unable to encode session constraints.")
	}
	var b bytes.Buffer
	writer := zlib.NewWriter(&b)
	if _, err := writer.Write(payload); err != nil {
		return 0, stsValidation("Unable to pack session constraints.")
	}
	if err := writer.Close(); err != nil {
		return 0, stsValidation("Unable to pack session constraints.")
	}
	// TODO: Comeback calibrate PackedPolicySize and packing rejection against AWS observations; the proprietary binary representation is not modeled yet.
	const limit = 4096
	size := (b.Len()*100 + limit - 1) / limit
	if size > 100 {
		return 0, &awswire.Error{Code: "PackedPolicyTooLarge", Message: "Packed session policies and tags exceed the local token capacity.", StatusCode: 400}
	}
	return int32(size), nil
}
