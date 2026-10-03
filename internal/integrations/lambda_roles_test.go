package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
	"stackd/internal/services/sts"
	"stackd/journal"
)

const lambdaTestFunction = "arn:aws:lambda:us-east-1:123456789012:function:f"

const lambdaTestTrust = `{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"ArnEquals":{"aws:SourceArn":"` + lambdaTestFunction + `"},"StringEquals":{"aws:SourceAccount":"123456789012","sts:RoleSessionName":"f"},"Bool":{"aws:PrincipalIsAWSService":"true"}}}}`

const lambdaTestPass = `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/execution","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"},"ArnEquals":{"iam:AssociatedResourceArn":"` + lambdaTestFunction + `"}}}}`

type lambdaRoleFixture struct {
	adapter    LambdaRoles
	repository iam.Repository
	clock      *clock.Manual
	ctx        context.Context
	scope      iam.Scope
	role       iam.Role
	user       iam.User
}

func newLambdaRoleFixture(t *testing.T) lambdaRoleFixture {
	t.Helper()
	f := lambdaRoleFixture{repository: iam.NewMemoryRepository(nil), clock: clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)), scope: iam.Scope{Partition: "aws", AccountID: "123456789012"}}
	f.role = iam.Role{Arn: "arn:aws:iam::123456789012:role/execution", RoleName: "execution", RoleId: "AROALAMBDAEXECUTION", MaxSessionDuration: 3600, AssumeRolePolicyDocument: lambdaTestTrust}
	f.user = iam.User{Arn: "arn:aws:iam::123456789012:user/deployer", UserName: "deployer", UserId: "AIDALAMBDADEPLOYER", IdentityPolicies: iam.IdentityPolicies{Inline: map[string]string{"pass": lambdaTestPass}}}
	f.ctx = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: f.scope.Partition, AccountID: f.scope.AccountID, Region: "us-east-1", PrincipalARN: f.user.Arn, PrincipalID: f.user.UserId, UserName: f.user.UserName})
	f.update(t, func(tx iam.WriteTx) error {
		if err := tx.PutUser(f.scope, f.user); err != nil {
			return err
		}
		return tx.PutRole(f.scope, f.role)
	})
	store := identity.NewWithConfig(identity.Config{AccountID: f.scope.AccountID, Repository: iam.NewCredentialRepository(f.repository, nil), Clock: f.clock})
	service := iam.NewWithConfig(iam.Config{Repository: f.repository, Credentials: store, Clock: f.clock})
	f.adapter = LambdaRoles{ServiceRoles: ServiceRoles{IAM: service, Credentials: store, Authorizer: authorization.NewWithClock(service, nil, f.clock)}}
	return f
}

func (f lambdaRoleFixture) update(t *testing.T, fn func(iam.WriteTx) error) {
	t.Helper()
	if err := f.repository.Update(f.ctx, fn); err != nil {
		t.Fatal(err)
	}
}

func TestLambdaDeploymentRequiresScopedPassRoleAndCurrentTrust(t *testing.T) {
	f := newLambdaRoleFixture(t)
	if err := f.adapter.Validate(f.ctx, f.role.Arn, lambdaTestFunction); err != nil {
		t.Fatal(err)
	}
	if err := f.adapter.Validate(f.ctx, f.role.Arn, lambdaTestFunction+"-other"); err == nil || err.Code != "AccessDenied" {
		t.Fatalf("associated function mismatch must deny PassRole: %v", err)
	}
	if err := f.adapter.Validate(f.ctx, strings.Replace(f.role.Arn, "123456789012", "999999999999", 1), lambdaTestFunction); err == nil {
		t.Fatal("cross-account execution role accepted")
	}
	if err := f.adapter.Validate(f.ctx, f.role.Arn+"-missing", lambdaTestFunction); err == nil {
		t.Fatal("missing execution role accepted")
	}
	f.user.IdentityPolicies.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	if err := f.adapter.Validate(f.ctx, f.role.Arn, lambdaTestFunction); err == nil || err.Code != "AccessDenied" {
		t.Fatalf("current explicit PassRole denial ignored: %v", err)
	}
	delete(f.user.IdentityPolicies.Inline, "deny")
	f.role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	f.update(t, func(tx iam.WriteTx) error {
		if err := tx.PutUser(f.scope, f.user); err != nil {
			return err
		}
		return tx.PutRole(f.scope, f.role)
	})
	if err := f.adapter.Validate(f.ctx, f.role.Arn, lambdaTestFunction); err == nil {
		t.Fatal("role not trusting Lambda accepted")
	}
}

func TestLambdaServiceSessionsUseCurrentRoleAndExpire(t *testing.T) {
	f := newLambdaRoleFixture(t)
	// Invocation need not retain the deployer's identity or PassRole permission.
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"})
	issued, apiErr := f.adapter.Assume(ctx, f.role.Arn, lambdaTestFunction, "f")
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	credential, err := f.adapter.Credentials.Resolve(ctx, issued.AccessKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if credential.PrincipalARN != "arn:aws:sts::123456789012:assumed-role/execution/f" || credential.PrincipalID != f.role.RoleId+":f" || credential.SecretAccessKey != issued.SecretAccessKey || credential.SessionToken == "" || credential.SessionToken != issued.SessionToken {
		t.Fatal("minted credentials do not resolve to the execution-role session")
	}
	requestCtx := awsctx.WithMetadata(ctx, awsctx.Metadata{Partition: "aws", AccountID: credential.AccountID, Region: "us-east-1", PrincipalARN: credential.PrincipalARN, PrincipalID: credential.PrincipalID, IssuerARN: credential.IssuerARN, IssuerID: credential.IssuerID, SessionType: string(credential.SessionType), TokenIssueTime: credential.CreateDate, SessionContext: credential.SessionContext})
	request := authorization.Request{Action: "sqs:SendMessage", ResourceARN: "arn:aws:sqs:us-east-1:123456789012:out"}
	if err := f.adapter.Authorizer.Authorize(requestCtx, request); err == nil {
		t.Fatal("empty execution role obtained deployer permissions")
	}
	f.role.IdentityPolicies.Inline = map[string]string{"send": `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"ArnEquals":{"lambda:SourceFunctionArn":"` + lambdaTestFunction + `"}}}}`}
	f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	if err := f.adapter.Authorizer.Authorize(requestCtx, request); err != nil {
		t.Fatalf("current role policy and authenticated function source not honored: %v", err)
	}
	// A boundary attached after issuance restricts the existing session.
	boundaryARN := "arn:aws:iam::123456789012:policy/boundary"
	f.role.PermissionsBoundary = &iam.Boundary{PermissionsBoundaryType: "Policy", PermissionsBoundaryArn: boundaryARN}
	f.update(t, func(tx iam.WriteTx) error {
		if err := tx.PutManagedPolicy(f.scope, iam.ManagedPolicy{Arn: boundaryARN, DefaultVersionId: "v1", Versions: map[string]*iam.PolicyVersion{"v1": {Document: `{"Statement":{"Effect":"Allow","Action":"sqs:ReceiveMessage","Resource":"*"}}`}}}); err != nil {
			return err
		}
		return tx.PutRole(f.scope, f.role)
	})
	if err := f.adapter.Authorizer.Authorize(requestCtx, request); err == nil {
		t.Fatal("new boundary did not restrict existing session")
	}
	f.role.PermissionsBoundary = nil
	f.role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	if _, err := f.adapter.Assume(ctx, f.role.Arn, lambdaTestFunction, "f"); err == nil {
		t.Fatal("revoked trust minted another environment credential")
	}
	if err := f.adapter.Authorizer.Authorize(requestCtx, request); err != nil {
		t.Fatalf("trust revocation incorrectly invalidated an already-issued session: %v", err)
	}
	f.update(t, func(tx iam.WriteTx) error { return tx.DeleteRole(f.scope, f.role.RoleName) })
	if _, err := f.adapter.Assume(ctx, f.role.Arn, lambdaTestFunction, "f"); err == nil {
		t.Fatal("deleted role minted another environment credential")
	}
	// Reusing the name/ARN must not restore the old immutable role identity.
	f.role.RoleId = "AROAREPLACEMENT"
	f.role.AssumeRolePolicyDocument = lambdaTestTrust
	f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	if err := f.adapter.Authorizer.Authorize(requestCtx, request); err == nil {
		t.Fatal("replacement role resurrected old session permissions")
	}
	if err := f.clock.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := f.adapter.Credentials.Resolve(ctx, issued.AccessKeyID); !errors.Is(err, identity.ErrExpired) {
		t.Fatalf("execution role session did not expire at service time: %v", err)
	}
}

type lambdaRoleAuditSink struct {
	reject       bool
	attemptedKey string
	events       []journal.Event
}

func (s *lambdaRoleAuditSink) AppendAPICallCompleted(_ context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if s.reject {
		var output struct {
			Credentials struct {
				AccessKeyID string `json:"accessKeyId"`
			} `json:"credentials"`
		}
		if err := json.Unmarshal(call.ResponseElements, &output); err != nil {
			return err
		}
		s.attemptedKey = output.Credentials.AccessKeyID
		return errors.New("reject service-role audit")
	}
	s.events = append(s.events, journal.Event{Envelope: envelope, APICallCompleted: &call})
	return nil
}

func TestLambdaAssumptionAuditsSTSOriginAndRollsBackCredential(t *testing.T) {
	f := newLambdaRoleFixture(t)
	sink := &lambdaRoleAuditSink{reject: true}
	f.adapter.STS = sts.NewWithDependencies(sts.Dependencies{Credentials: f.adapter.Credentials, Clock: f.clock, APIEvents: apievents.New(sink)})
	model, _ := awscatalog.LookupService("lambda")
	operation, _ := model.Operation("Invoke")
	ctx := awsapi.WithDecodedRequest(f.ctx, awsapi.DecodedRequest{Operation: operation, Input: struct{ Payload string }{"private-lambda-payload"}})
	metadata := awsctx.FromContext(ctx)
	metadata.RequestID, metadata.ParentEventID = "parent-lambda-request", "parent-event"
	ctx = awsctx.WithMetadata(ctx, metadata)
	issued, apiErr := f.adapter.Assume(ctx, f.role.Arn, lambdaTestFunction, "f")
	if apiErr == nil || issued.AccessKeyID != "" || sink.attemptedKey == "" {
		t.Fatal("audit failure published an execution credential", apiErr)
	}
	if _, err := f.adapter.Credentials.Resolve(ctx, sink.attemptedKey); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("failed audit retained execution credential: %v", err)
	}
	sink.reject, sink.events = false, nil
	issued, apiErr = f.adapter.Assume(ctx, f.role.Arn, lambdaTestFunction, "f")
	if apiErr != nil {
		t.Fatal(apiErr)
	}
	if len(sink.events) != 1 {
		t.Fatal("one role assumption did not produce one STS outcome")
	}
	event := sink.events[0]
	document, err := apievents.CloudTrailRecord(event)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(document, &record); err != nil {
		t.Fatal(err)
	}
	if record["eventName"] != "AssumeRole" || record["eventSource"] != "sts.amazonaws.com" || record["readOnly"] != true || record["eventCategory"] != "Management" {
		t.Fatalf("service assumption inherited Lambda classification: %s", document)
	}
	if event.RequestID == "" || event.RequestID == metadata.RequestID || event.ParentEventID != metadata.ParentEventID || !event.At.Equal(f.clock.Now()) {
		t.Fatal("service assumption lost its distinct causal origin", event.Envelope)
	}
	caller := record["userIdentity"].(map[string]any)
	if caller["type"] != "AWSService" || caller["invokedBy"] != "lambda.amazonaws.com" || caller["arn"] != nil || caller["accessKeyId"] != nil {
		t.Fatalf("service assumption inherited deployment identity: %#v", caller)
	}
	if strings.Contains(string(document), "private-lambda-payload") || strings.Contains(string(document), issued.SecretAccessKey) || strings.Contains(string(document), issued.SessionToken) {
		t.Fatal("parent input or session secret entered STS audit")
	}
	if _, err := f.adapter.Credentials.Resolve(ctx, issued.AccessKeyID); err != nil {
		t.Fatal("successful STS audit failed to commit execution credential", err)
	}
}
