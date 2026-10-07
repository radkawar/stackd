package integrations

// These concrete adapters share IAM's identical inline-policy lifecycle, with
// fixed owner identity kinds rather than a generic CFN CRUD implementation.
type cfnIAMUserPolicy struct{ cfnIAMInlineAttachment }
type cfnIAMGroupPolicy struct{ cfnIAMInlineAttachment }
type cfnIAMRolePolicy struct{ cfnIAMInlineAttachment }
