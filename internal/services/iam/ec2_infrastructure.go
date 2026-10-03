package iam

import (
	"context"
	"fmt"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/journal"
)

const ec2InfrastructureRole = "aws:ec2-infrastructure"

type ec2InfrastructureContextKey struct{}

// EC2InfrastructureContext authenticates EC2's internal identity-only actor. It
// issues no credentials and creates no customer-visible IAM role. Only trusted
// compute adapters call this after resolving the instance's authoritative scope.
// KMS grants provide authority; ordinary key-policy and SCP evaluation still apply.
//
// The returned context preserves transaction/causal values and routing scope, but
// replaces every launcher credential, session policy and transport attribute. The
// issuer and principal IDs follow the captured native KMS AssumedRole identity.
func (s *Service) EC2InfrastructureContext(ctx context.Context, instanceID string) (context.Context, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	origin := awsctx.FromContext(ctx)
	if origin.Partition == "" || origin.Region == "" || !ec2InfrastructureAccount(origin.AccountID) || !ec2InfrastructureInstance(instanceID) {
		return nil, fmt.Errorf("invalid EC2 infrastructure identity scope")
	}
	principal := ec2InfrastructurePrincipal(origin.Partition, origin.AccountID, instanceID)
	metadata := awsctx.Metadata{
		Partition: origin.Partition, AccountID: origin.AccountID, Region: origin.Region,
		RequestID: origin.RequestID, ParentEventID: origin.ParentEventID,
		PrincipalARN: principal.ARN, PrincipalID: principal.ID,
		SessionType: "AssumeRole", UserName: instanceID,
		IssuerARN:      "arn:" + origin.Partition + ":iam::" + origin.AccountID + ":role/" + ec2InfrastructureRole,
		IssuerID:       origin.AccountID + ":" + ec2InfrastructureRole,
		TokenIssueTime: s.clock.Now().UTC(),
		InvokedBy:      "AWS Internal", UserAgent: "AWS Internal",
		InScopeOf: journal.APIIdentityScope{
			IssuerType:          "AWS::EC2::Instance",
			CredentialsIssuedTo: "arn:" + origin.Partition + ":ec2:" + origin.Region + ":" + origin.AccountID + ":instance/" + instanceID,
		},
	}
	return context.WithValue(awsctx.WithMetadata(ctx, metadata), ec2InfrastructureContextKey{}, principal), nil
}

// IsEC2InfrastructureContext identifies the credential-free internal actor, not
// an ARN supplied by an HTTP caller. It lets integrations omit credential-usage
// accounting without treating this role as an SCP-exempt AWS service principal.
func IsEC2InfrastructureContext(ctx context.Context) bool {
	principal, ok := ctx.Value(ec2InfrastructureContextKey{}).(authorization.Principal)
	if !ok {
		return false
	}
	m := awsctx.FromContext(ctx)
	return m.PrincipalARN == principal.ARN && m.PrincipalID == principal.ID &&
		m.IssuerARN == "arn:"+m.Partition+":iam::"+m.AccountID+":role/"+ec2InfrastructureRole &&
		m.IssuerID == m.AccountID+":"+ec2InfrastructureRole && m.ServicePrincipal.Name == "" &&
		m.AccessKeyID == "" && !m.HasSessionPolicy && len(m.SessionPolicies) == 0 && len(m.SessionPolicyARNs) == 0
}

func ec2InfrastructurePrincipal(partition, account, instanceID string) authorization.Principal {
	return authorization.Principal{
		ARN: "arn:" + partition + ":sts::" + account + ":assumed-role/" + ec2InfrastructureRole + "/" + instanceID,
		ID:  account + ":" + ec2InfrastructureRole + ":" + instanceID,
	}
}

func ec2InfrastructureAccount(account string) bool {
	return len(account) == 12 && strings.Trim(account, "0123456789") == ""
}

// IsEC2InfrastructurePrincipal recognizes a resolved grant binding in the given
// owner account. This does not authenticate a request or grant any permission.
func IsEC2InfrastructurePrincipal(partition, account, arn, id string) bool {
	principal, ok := ec2InfrastructureReference(partition, arn)
	return ok && principal.ARN == arn && principal.ID == id && strings.HasPrefix(id, account+":")
}

func ec2InfrastructureInstance(id string) bool {
	suffix, ok := strings.CutPrefix(id, "i-")
	return ok && (len(suffix) == 8 || len(suffix) == 17) && strings.Trim(suffix, "0123456789abcdef") == ""
}

// ec2InfrastructureReference resolves the reserved named session without an IAM
// role record, just as other grant sessions need not have credentials issued yet.
func ec2InfrastructureReference(partition, reference string) (authorization.Principal, bool) {
	var account, instanceID string
	if strings.HasPrefix(reference, "arn:") {
		parts := strings.SplitN(reference, ":", 6)
		if len(parts) != 6 || parts[1] != partition || parts[2] != "sts" || parts[3] != "" {
			return authorization.Principal{}, false
		}
		var ok bool
		instanceID, ok = strings.CutPrefix(parts[5], "assumed-role/"+ec2InfrastructureRole+"/")
		if !ok {
			return authorization.Principal{}, false
		}
		account = parts[4]
	} else {
		var rest string
		account, rest, _ = strings.Cut(reference, ":")
		var ok bool
		instanceID, ok = strings.CutPrefix(rest, ec2InfrastructureRole+":")
		if !ok {
			return authorization.Principal{}, false
		}
	}
	if !ec2InfrastructureAccount(account) || !ec2InfrastructureInstance(instanceID) {
		return authorization.Principal{}, false
	}
	return ec2InfrastructurePrincipal(partition, account, instanceID), true
}
