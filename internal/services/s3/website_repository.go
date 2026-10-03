package s3

// WebsiteConfiguration is admitted website state: an index with optional error
// document/rules, or a redirect-all target, never both modes. Nil denotes absence.
type WebsiteConfiguration struct {
	IndexSuffix, ErrorKey *string
	RedirectAll           *WebsiteRedirectAll
	Rules                 []WebsiteRoutingRule
}

type WebsiteRedirectAll struct {
	HostName string
	Protocol *string
}

// WebsiteRoutingRule retains condition presence and first-match ordering.
// Redirect is required; absent and explicitly empty replacements differ.
type WebsiteRoutingRule struct {
	Condition *WebsiteCondition
	Redirect  WebsiteRedirect
}

type WebsiteCondition struct {
	KeyPrefix, ErrorCode *string
}

type WebsiteRedirect struct {
	HostName, Protocol, StatusCode *string
	ReplaceKeyPrefix, ReplaceKey   *string
}
