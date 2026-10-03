package identity

import (
	"context"
	"strings"
	"time"

	"stackd/iam/policy"
)

// RootSessionSpec is an already-authorized Organizations root assumption.
// The consumer resolves TaskPolicyDocument from the default version of the
// selected AWS task policy before issuance; the resulting scope is immutable.
type RootSessionSpec struct {
	AccountID, Partition              string
	TaskPolicyARN, TaskPolicyDocument string
	Duration                          time.Duration
}

// ValidRootTaskPolicyARN accepts the five AWS-managed task policies supported
// by AssumeRoot. Policy documents remain supplied by the managed-policy source.
func ValidRootTaskPolicyARN(partition, arn string) bool {
	prefix := "arn:" + partition + ":iam::aws:policy/root-task/"
	if partition == "" || !strings.HasPrefix(arn, prefix) {
		return false
	}
	switch strings.TrimPrefix(arn, prefix) {
	case "IAMAuditRootUserCredentials", "IAMCreateRootUserPassword", "IAMDeleteRootUserCredentials", "S3UnlockBucketPolicy", "SQSUnlockQueuePolicy":
		return true
	default:
		return false
	}
}

// IssueRootSession atomically revalidates the caller and issues a task-scoped
// root principal in the target account. Only live long-term IAM user keys and
// assumed-role sessions may issue root sessions. A zero duration is valid and
// produces credentials that expire at the captured transaction instant.
func (s *Store) IssueRootSession(ctx context.Context, parent Credential, spec RootSessionSpec) (Credential, error) {
	if spec.Duration < 0 || spec.Duration > 15*time.Minute {
		return Credential{}, ErrInvalidDuration
	}
	root := Principal{AccountID: spec.AccountID, ID: spec.AccountID, ARN: "arn:" + spec.Partition + ":iam::" + spec.AccountID + ":root"}
	if !validPrincipal(root) || !ValidRootTaskPolicyARN(spec.Partition, spec.TaskPolicyARN) {
		return Credential{}, ErrInvalidPrincipal
	}
	if _, err := policy.Parse([]byte(spec.TaskPolicyDocument)); err != nil {
		return Credential{}, err
	}
	return s.issue(ctx, parent, func(current Credential, instant time.Time) (Credential, error) {
		if !rootSessionCaller(current, spec.Partition) {
			return Credential{}, ErrInvalidPrincipal
		}
		credential, err := newCredential(root, "ASIA", instant)
		if err != nil {
			return Credential{}, err
		}
		credential.SessionType = SessionTypeAssumeRoot
		credential.Expiration = instant.Add(spec.Duration)
		credential.HasSessionPolicy = true
		credential.SessionPolicies = []string{spec.TaskPolicyDocument}
		credential.SessionPolicyARNs = []string{spec.TaskPolicyARN}
		credential.SourceIdentity = current.SourceIdentity
		return credential, nil
	})
}

func rootSessionCaller(c Credential, partition string) bool {
	parts := strings.SplitN(c.PrincipalARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != partition || parts[3] != "" || parts[4] != c.AccountID {
		return false
	}
	if c.SessionType == "" && c.SessionToken == "" {
		return parts[2] == "iam" && strings.HasPrefix(parts[5], "user/") && len(parts[5]) > len("user/")
	}
	return c.SessionType == SessionTypeAssumeRole && c.SessionToken != "" && parts[2] == "sts" && strings.HasPrefix(parts[5], "assumed-role/")
}
