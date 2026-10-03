package awswire

import "strings"

// JSONTarget separates an AWS JSON target into its canonical service prefix and
// operation. It preserves the request header: SigV4 verifies the original bytes.
func JSONTarget(target string) (prefix, operation string, ok bool) {
	separator := strings.LastIndexByte(target, '.')
	if separator < 0 {
		return target, "", false
	}
	prefix, operation = target[:separator], target[separator+1:]
	// The AWS CLI and JavaScript SDK v2 use this legacy targetPrefix; the current Smithy
	// model/Go v2 SDK use CloudTrail_20131101. This is an exact observed alias,
	// not permission for arbitrary namespaces before an operation.
	// Source: aws-sdk/apis/cloudtrail-2013-11-01.min.json metadata.targetPrefix.
	if prefix == "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101" {
		prefix = "CloudTrail_20131101"
	}
	return prefix, operation, true
}
