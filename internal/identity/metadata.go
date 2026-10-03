package identity

import (
	"fmt"
	"strings"
	"time"

	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
)

// RequestMetadata projects a resolved credential into a request's routing scope.
// Callers own authentication: the gateway verifies the signature, while internal
// service adapters use credentials issued to their actual execution environment.
// Session collections are detached by awsctx.WithMetadata when entering context.
func RequestMetadata(credential Credential, accessKey, region, requestID string) (awsctx.Metadata, error) {
	account := credential.AccountID
	if !accountPattern.MatchString(account) || credential.AccessKeyID != accessKey {
		return awsctx.Metadata{}, fmt.Errorf("invalid local credential scope")
	}
	partition := "aws"
	if strings.HasPrefix(region, "cn-") {
		partition = "aws-cn"
	} else if strings.HasPrefix(region, "us-gov-") {
		partition = "aws-us-gov"
	}
	principalARN := credential.PrincipalARN
	if credential.PrincipalID == account && credential.SessionType == "" && (accessKey == "test" || accessKey == account) {
		principalARN = "arn:" + partition + ":iam::" + account + ":root"
	}
	if !strings.HasPrefix(principalARN, "arn:"+partition+":") {
		return awsctx.Metadata{}, fmt.Errorf("the credential belongs to another AWS partition")
	}
	if credential.DefaultRegionsOnly && region != "aws-global" && !awscatalog.SupportsLegacySTSTokens(region) {
		return awsctx.Metadata{}, fmt.Errorf("the security token is invalid in this region")
	}
	var issueTime time.Time
	if credential.SessionType != "" {
		issueTime = credential.CreateDate
	}
	return awsctx.Metadata{
		AccountID: account, Region: region, Partition: partition, AccessKeyID: accessKey,
		RequestID: requestID, PrincipalARN: principalARN, PrincipalID: credential.PrincipalID, UserName: credential.UserName,
		SessionType: string(credential.SessionType), IssuerARN: credential.IssuerARN, IssuerID: credential.IssuerID,
		SessionPolicies: credential.SessionPolicies, HasSessionPolicy: credential.HasSessionPolicy,
		SessionPolicyARNs: credential.SessionPolicyARNs, SessionContext: credential.SessionContext,
		FederatedProvider: credential.FederatedProvider,
		SessionTags:       credential.SessionTags, TransitiveTagKeys: credential.TransitiveTagKeys, SourceIdentity: credential.SourceIdentity,
		MFAPresent: credential.MFAPresent, MFAAuthenticatedAt: credential.MFAAuthenticatedAt, TokenIssueTime: issueTime,
		InScopeOf: credential.InScopeOf,
	}, nil
}
