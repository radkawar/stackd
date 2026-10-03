package authorization_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
)

func rootTaskDocuments(t *testing.T) map[string]string {
	t.Helper()
	var fixture struct {
		Observations []struct {
			Case   string
			Output struct {
				PolicyVersion struct{ Document json.RawMessage }
			}
		}
	}
	data, err := os.ReadFile("../../testdata/aws/iam/root_access.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	documents := make(map[string]string)
	for _, row := range fixture.Observations {
		if name, found := strings.CutPrefix(row.Case, "public_policy_version_"); found {
			documents[name] = string(row.Output.PolicyVersion.Document)
		}
	}
	return documents
}

func rootTaskMetadata(t *testing.T, documents map[string]string, name string) awsctx.Metadata {
	t.Helper()
	document, found := documents[name]
	if !found || document == "" {
		t.Fatalf("captured task policy %q is missing", name)
	}
	m := metadata(true)
	m.SessionType = "AssumeRoot"
	m.HasSessionPolicy = true
	m.SessionPolicies = []string{document}
	m.SessionPolicyARNs = []string{"arn:aws:iam::aws:policy/root-task/" + name}
	return m
}

func TestAssumeRootTaskPoliciesAWSReplay(t *testing.T) {
	documents := rootTaskDocuments(t)
	rootARN := metadata(true).PrincipalARN
	for _, test := range []struct {
		name, task, action, resource string
		allow                        bool
	}{
		{"audit account", "IAMAuditRootUserCredentials", "iam:GetAccountSummary", "*", true},
		{"audit root", "IAMAuditRootUserCredentials", "iam:ListAccessKeys", rootARN, true},
		{"audit cannot create keys", "IAMAuditRootUserCredentials", "iam:CreateAccessKey", rootARN, false},
		{"audit cannot inspect user", "IAMAuditRootUserCredentials", "iam:GetLoginProfile", userARN, false},
		{"create password", "IAMCreateRootUserPassword", "iam:CreateLoginProfile", rootARN, true},
		{"get new password profile", "IAMCreateRootUserPassword", "iam:GetLoginProfile", rootARN, true},
		{"create cannot delete password", "IAMCreateRootUserPassword", "iam:DeleteLoginProfile", rootARN, false},
		{"create cannot change user", "IAMCreateRootUserPassword", "iam:CreateLoginProfile", userARN, false},
		{"delete key", "IAMDeleteRootUserCredentials", "iam:DeleteAccessKey", rootARN, true},
		{"delete MFA", "IAMDeleteRootUserCredentials", "iam:DeleteVirtualMFADevice", rootARN, true},
		{"delete does not include account audit", "IAMDeleteRootUserCredentials", "iam:GetAccountSummary", "*", false},
		{"delete cannot change user", "IAMDeleteRootUserCredentials", "iam:DeleteLoginProfile", userARN, false},
		{"read bucket policy", "S3UnlockBucketPolicy", "s3:GetBucketPolicy", "arn:aws:s3:::example", true},
		{"update bucket policy", "S3UnlockBucketPolicy", "s3:PutBucketPolicy", "arn:aws:s3:::example", true},
		{"unlock cannot read object", "S3UnlockBucketPolicy", "s3:GetObject", "arn:aws:s3:::example/object", false},
		{"read own queue attributes", "SQSUnlockQueuePolicy", "sqs:GetQueueAttributes", queueARN, true},
		{"update own queue attributes", "SQSUnlockQueuePolicy", "sqs:SetQueueAttributes", queueARN, true},
		{"unlock cannot send message", "SQSUnlockQueuePolicy", "sqs:SendMessage", queueARN, false},
		{"unlock cannot inspect foreign queue", "SQSUnlockQueuePolicy", "sqs:GetQueueAttributes", "arn:aws:sqs:us-east-1:999999999999:queue", false},
		{"caller identity remains permissionless", "IAMAuditRootUserCredentials", "sts:GetCallerIdentity", "*", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := rootTaskMetadata(t, documents, test.task)
			e := authorization.New(nil, nil)
			err := e.Authorize(awsctx.WithMetadata(t.Context(), m), authorization.Request{Action: test.action, ResourceARN: test.resource})
			if (err == nil) != test.allow {
				t.Fatalf("%s %s: error=%v want allow=%v", test.action, test.resource, err, test.allow)
			}
		})
	}
}

func TestAssumeRootTaskDenialsPrecedeResourceGrants(t *testing.T) {
	documents := rootTaskDocuments(t)
	m := rootTaskMetadata(t, documents, "SQSUnlockQueuePolicy")
	ctx := awsctx.WithMetadata(t.Context(), m)
	e := authorization.New(nil, nil)
	for _, resourcePolicy := range []string{
		`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sqs:*","Resource":"*"}}`,
		`{"Statement":{"Effect":"Allow","Principal":{"AWS":"` + m.PrincipalARN + `"},"Action":"sqs:*","Resource":"*"}}`,
	} {
		for _, request := range []authorization.Request{
			{Action: "sqs:SendMessage", ResourceARN: queueARN, ResourcePolicies: []authorization.BoundPolicy{{Document: resourcePolicy}}},
			{Action: "sqs:GetQueueAttributes", ResourceARN: "arn:aws:sqs:us-east-1:999999999999:queue", ResourcePolicies: []authorization.BoundPolicy{{Document: resourcePolicy}}},
		} {
			if err := e.Authorize(ctx, request); err == nil || !strings.Contains(err.Message, "session policy explicitly denies") {
				t.Fatalf("resource grant bypassed task ceiling: %s %v", request.Action, err)
			}
		}
	}
	if err := e.Authorize(ctx, authorization.Request{Action: "kms:Decrypt", ResourceARN: "arn:aws:kms:us-east-1:999999999999:key/example", RequireResourcePolicy: true, Grants: iampolicy.GrantPermissions{Direct: true, TrustedDirect: true}}); err == nil || !strings.Contains(err.Message, "session policy explicitly denies") {
		t.Fatalf("KMS grant bypassed task ceiling: %v", err)
	}
	request := authorization.Request{Action: "sqs:GetQueueAttributes", ResourceARN: queueARN, ResourcePolicies: []authorization.BoundPolicy{{Document: `{"Statement":{"Effect":"Deny","Principal":"*","Action":"sqs:GetQueueAttributes","Resource":"*"}}`}}}
	if err := e.Authorize(ctx, request); err == nil || !strings.Contains(err.Message, "resource policy explicitly denies") {
		t.Fatalf("task exception bypassed ordinary resource denial: %v", err)
	}
}

type targetRootControls struct {
	account string
	levels  []iampolicy.PolicyLevel
}

func (s targetRootControls) ServiceControlPolicies(ctx context.Context) ([]iampolicy.PolicyLevel, error) {
	if awsctx.FromContext(ctx).AccountID != s.account {
		return nil, nil
	}
	return s.levels, nil
}

func TestAssumeRootTargetAccountSCPsAndContext(t *testing.T) {
	documents := rootTaskDocuments(t)
	m := rootTaskMetadata(t, documents, "IAMAuditRootUserCredentials")
	m.SourceIdentity = "management-user"
	full := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	denyAudit := `{"Statement":{"Effect":"Deny","Action":"iam:GetAccountSummary","Resource":"*"}}`
	// This is the documented SCP pattern that blocks long-term root usage
	// while permitting an AssumeRoot session's task-scoped operations.
	denyLongTermRoot := `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:root"},"Null":{"aws:AssumedRoot":"true"}}}}`
	request := authorization.Request{Action: "iam:GetAccountSummary", ResourceARN: "*"}
	for _, test := range []struct {
		name   string
		levels []iampolicy.PolicyLevel
		allow  bool
	}{
		{"no restriction", nil, true},
		{"explicit target deny", []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: full}, {Document: denyAudit}}}}, false},
		{"target level lacks grant", []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: full}}}, {}}, false},
		{"AssumedRoot condition", []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: full}, {Document: denyLongTermRoot}}}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := authorization.New(nil, targetRootControls{account: m.AccountID, levels: test.levels})
			err := e.Authorize(awsctx.WithMetadata(t.Context(), m), request)
			if (err == nil) != test.allow {
				t.Fatalf("SCP error=%v want allow=%v", err, test.allow)
			}
		})
	}
	e := authorization.New(nil, targetRootControls{account: m.AccountID, levels: []iampolicy.PolicyLevel{{Documents: []iampolicy.Policy{{Document: full}, {Document: denyLongTermRoot}}}}})
	if err := e.Authorize(awsctx.WithMetadata(t.Context(), metadata(true)), request); err == nil {
		t.Fatal("long-term root acquired assumed-root context")
	}
	ordinary := roleMetadata()
	ordinary.HasSessionPolicy, ordinary.SessionPolicies = true, m.SessionPolicies
	if err := authorization.New(identitySource{set: authorization.PolicySet{Identity: []iampolicy.Policy{{Document: full}}}}, nil).Authorize(awsctx.WithMetadata(t.Context(), ordinary), request); err == nil {
		t.Fatal("ordinary role session gained deny-only task semantics")
	}
	m.SessionPolicies = []string{`{"Statement":{"Effect":"Allow","Action":"iam:GetAccountSummary","Resource":"*","Condition":{"Unknown":{"key":"value"}}}}`}
	if err := authorization.New(nil, nil).Authorize(awsctx.WithMetadata(t.Context(), m), request); err == nil || !strings.Contains(err.Message, "Policy evaluation failed") {
		t.Fatalf("unsupported task document failed open: %v", err)
	}
}

func TestAssumeRootCallerCrossAccountAuthorization(t *testing.T) {
	target := "arn:aws:iam::999999999999:root"
	grant := `{"Statement":{"Effect":"Allow","Action":"sts:AssumeRoot","Resource":"` + target + `"}}`
	denyAssumption := `{"Statement":{"Effect":"Deny","Action":"sts:AssumeRoot","Resource":"*"}}`
	all := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	for _, test := range []struct {
		name, action, resource, resourcePolicy string
		policies, boundary, session            []string
		controls                               controlSource
		allow                                  bool
	}{
		{name: "caller permission required"},
		{name: "caller grants target root", policies: []string{grant}, allow: true},
		{name: "identity deny", policies: []string{grant, denyAssumption}},
		{name: "boundary implicit deny", policies: []string{grant}, boundary: []string{allow}},
		{name: "boundary explicit deny", policies: []string{grant}, boundary: []string{all, denyAssumption}},
		{name: "session implicit deny", policies: []string{grant}, session: []string{allow}},
		{name: "session explicit deny", policies: []string{grant}, session: []string{all, denyAssumption}},
		{name: "caller SCP deny", policies: []string{grant}, controls: controlSource{{Documents: []iampolicy.Policy{{Document: all}, {Document: denyAssumption}}}}},
		{name: "all caller ceilings allow", policies: []string{grant}, boundary: []string{grant}, session: []string{grant}, controls: controlSource{{Documents: []iampolicy.Policy{{Document: grant}}}}, allow: true},
		{name: "resource cannot replace caller grant", resourcePolicy: strings.ReplaceAll(direct, "sqs:*", "sts:AssumeRoot")},
		{name: "target user is not root", policies: []string{all}, resource: "arn:aws:iam::999999999999:user/alice"},
		{name: "target role is not root", policies: []string{all}, resource: "arn:aws:iam::999999999999:role/worker"},
		{name: "STS resource is not IAM root", policies: []string{all}, resource: "arn:aws:sts::999999999999:root"},
		{name: "target partition differs", policies: []string{all}, resource: "arn:aws-cn:iam::999999999999:root"},
		{name: "AssumeRole retains target trust requirement", policies: []string{all}, action: "sts:AssumeRole", resource: "arn:aws:iam::999999999999:role/worker"},
		{name: "other STS actions retain cross account rules", policies: []string{all}, action: "sts:GetFederationToken"},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := metadata(false)
			if test.session != nil {
				m = roleMetadata()
				m.HasSessionPolicy, m.SessionPolicies = true, test.session
			}
			request := authorization.Request{Action: test.action, ResourceARN: test.resource, ResourcePolicies: []authorization.BoundPolicy{{Document: test.resourcePolicy}}}
			if request.Action == "" {
				request.Action = "sts:AssumeRoot"
			}
			if request.ResourceARN == "" {
				request.ResourceARN = target
			}
			source := identitySource{set: authorization.PolicySet{Identity: policyDocuments(test.policies...), Boundary: policyDocuments(test.boundary...), HasBoundary: test.boundary != nil}}
			err := authorization.New(source, test.controls).Authorize(awsctx.WithMetadata(t.Context(), m), request)
			if (err == nil) != test.allow {
				t.Fatalf("caller error=%v want allow=%v", err, test.allow)
			}
		})
	}
}
