package organizations

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"

	iampolicy "stackd/iam/policy"
	"stackd/internal/awswire"
	"stackd/internal/iam/catalog"
)

type policyDocument struct {
	Version   string
	Statement json.RawMessage
}
type policyStatement struct {
	Effect                                                            string
	Action, NotAction, Resource, NotResource, Principal, NotPrincipal json.RawMessage
}

func (s *operationState) validatePolicy(content, kind string) *awswire.Error {
	data := bytes.TrimSpace([]byte(content))
	if len(data) == 0 || data[0] != '{' || !utf8.Valid(data) || !json.Valid(data) {
		return failure("MalformedPolicyDocumentException", "Policy content must be a JSON object.")
	}
	if utf8.RuneCountInString(content) > policyDocumentLimit(kind) {
		return failure("ConstraintViolationException", "POLICY_CONTENT_LIMIT_EXCEEDED")
	}
	if kind != "SERVICE_CONTROL_POLICY" && kind != "RESOURCE_CONTROL_POLICY" {
		// TODO: Comeback complete the remaining management-policy service schemas/defaults, tag JSON constraints, chat effective-document diagnostic limits, downstream service enforcement/compliance and native delegated-access/propagation conformance beyond the tag, backup, AI admission and chat publication captures.
		n, err := parseManagementPolicy(data, kind)
		if err == nil {
			switch kind {
			case "TAG_POLICY":
				err = tagPolicy(n)
			case "BACKUP_POLICY":
				err = backupPolicy(n, s.instant)
			case "AISERVICES_OPT_OUT_POLICY":
				err = aiOptOutPolicy(n)
			case "CHATBOT_POLICY":
				err = chatPolicy(n)
			case "S3_POLICY":
				err = s3Policy(n)
			case "DECLARATIVE_POLICY_EC2":
				err = ec2SnapshotPolicy(n)
			}
		}
		if err != nil {
			return failure("MalformedPolicyDocumentException", "The provided policy document does not meet the requirements of the specified policy type.")
		}
		return nil
	}
	if kind == "RESOURCE_CONTROL_POLICY" {
		if _, err := iampolicy.ParseResourceControl(data, catalog.SupportsResourceControlPolicy); err != nil {
			return failure("MalformedPolicyDocumentException", "The provided policy document does not meet the requirements of the specified policy type.")
		}
		return nil
	}
	var doc policyDocument
	if json.Unmarshal(data, &doc) != nil || (doc.Version != "" && doc.Version != "2012-10-17" && doc.Version != "2008-10-17") {
		return failure("MalformedPolicyDocumentException", "Invalid policy document version.")
	}
	var statements []policyStatement
	if len(doc.Statement) > 0 && doc.Statement[0] == '{' {
		var statement policyStatement
		if json.Unmarshal(doc.Statement, &statement) != nil {
			return failure("MalformedPolicyDocumentException", "Invalid policy statement.")
		}
		statements = []policyStatement{statement}
	} else if json.Unmarshal(doc.Statement, &statements) != nil {
		return failure("MalformedPolicyDocumentException", "Statement must be an object or array.")
	}
	if len(statements) == 0 {
		return failure("MalformedPolicyDocumentException", "At least one Statement is required.")
	}
	for _, st := range statements {
		if st.Effect != "Allow" && st.Effect != "Deny" {
			return failure("MalformedPolicyDocumentException", "Statement Effect must be Allow or Deny.")
		}
		if !oneStringSet(st.Action, st.NotAction) || !oneStringSet(st.Resource, st.NotResource) {
			return failure("MalformedPolicyDocumentException", "Each statement requires Action or NotAction, and Resource or NotResource.")
		}
		if len(st.Principal) != 0 || len(st.NotPrincipal) != 0 {
			return failure("MalformedPolicyDocumentException", "Service control policies do not support Principal.")
		}
	}
	return nil
}

// These quotas follow the AWS Organizations service limits reference. Policy
// content supplied through the SDK counts whitespace as well as JSON data.
func policyDocumentLimit(kind string) int {
	switch kind {
	case "SERVICE_CONTROL_POLICY":
		return 10240
	case "RESOURCE_CONTROL_POLICY":
		return 5120
	case "AISERVICES_OPT_OUT_POLICY":
		return 2500
	default:
		return 10000
	}
}

func policyAttachmentLimit(kind string) int {
	switch kind {
	case "SERVICE_CONTROL_POLICY", "DECLARATIVE_POLICY_EC2", "BACKUP_POLICY", "TAG_POLICY", "SECURITYHUB_POLICY":
		return 10
	default:
		return 5
	}
}

func policyCountLimit(kind string) int {
	switch kind {
	case "SERVICE_CONTROL_POLICY":
		return 10000
	case "RESOURCE_CONTROL_POLICY":
		return 2000
	default:
		return 1000
	}
}

func oneStringSet(a, b json.RawMessage) bool {
	if (len(a) == 0) == (len(b) == 0) {
		return false
	}
	if len(a) == 0 {
		a = b
	}
	var scalar string
	if json.Unmarshal(a, &scalar) == nil {
		return scalar != ""
	}
	var list []string
	if json.Unmarshal(a, &list) != nil || len(list) == 0 {
		return false
	}
	for _, item := range list {
		if item == "" {
			return false
		}
	}
	return true
}
