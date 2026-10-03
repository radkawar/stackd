package integrations

import (
	"errors"
	"net/url"
	"testing"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/guardduty"
	"stackd/internal/services/iam"
)

func TestGuardDutyIPListExactGrantAndCurrentCallerDenial(t *testing.T) {
	f := newLambdaRoleFixture(t)
	service := f.adapter.ServiceRoles.IAM.(*iam.Service)
	t.Cleanup(func() { _ = service.Close() })
	if err := service.RegisterServiceLinkedRole(GuardDutyRoleTemplate(), GuardDutyRoleUsage{}); err != nil {
		t.Fatal(err)
	}
	if err := service.ProvisionServiceLinkedRole(f.ctx, f.scope, guardduty.ServicePrincipal); err != nil {
		t.Fatal(err)
	}
	list := guardduty.IPList{Scope: guardduty.Scope{Partition: "aws", AccountID: f.scope.AccountID, Region: "us-east-1"}, ARN: "arn:aws:guardduty:us-east-1:123456789012:detector/d/ipset/i", Location: "https://bucket.s3.us-east-1.amazonaws.com/path/list%20one%2B.txt"}
	f.user.Inline = map[string]string{"manage": `{"Statement":{"Effect":"Allow","Action":["iam:PutRolePolicy","iam:DeleteRolePolicy"],"Resource":"` + guardDutyListRole(list) + `"}}`}
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	a := GuardDutyIPLists{IAM: service, Roles: f.adapter.ServiceRoles, Authorizer: f.adapter.Authorizer}
	if err := a.PutPolicy(f.ctx, list); err != nil {
		t.Fatal(err)
	}
	credential, wire := a.Roles.assume(f.ctx, awsctx.ServicePrincipal{Name: guardduty.ServicePrincipal, Type: "AWSService"}, guardDutyListRole(list), identity.RoleSessionSpec{SessionName: "list-test"}, "")
	if wire != nil {
		t.Fatal(wire)
	}
	ctx, wire := serviceRoleRequestContext(f.ctx, credential, list.Region, guardduty.ServicePrincipal)
	if wire != nil {
		t.Fatal(wire)
	}
	exact := "arn:aws:s3:::bucket/path/list one+.txt"
	for _, action := range []string{"s3:GetObject", "s3:GetObjectVersion"} {
		if denied := a.Authorizer.Authorize(ctx, authorization.Request{Action: action, ResourceARN: exact}); denied != nil {
			t.Fatalf("declared object denied: %v", denied)
		}
		if denied := a.Authorizer.Authorize(ctx, authorization.Request{Action: action, ResourceARN: exact + "-other"}); denied == nil {
			t.Fatal("source grant expanded to an undeclared object")
		}
	}
	f.user.Inline["deny"] = `{"Statement":{"Effect":"Deny","Action":["iam:PutRolePolicy","iam:DeleteRolePolicy"],"Resource":"*"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	for _, command := range []func() error{func() error { return a.PutPolicy(f.ctx, list) }, func() error { return a.DeletePolicy(f.ctx, list) }} {
		var denied *awswire.Error
		if err := command(); !errors.As(err, &denied) || denied.Code != "AccessDenied" {
			t.Fatalf("current caller denial = %v", err)
		}
	}
	delete(f.user.Inline, "deny")
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	list.Location = "s3://bucket/replacement.txt"
	if err := a.PutPolicy(f.ctx, list); err != nil {
		t.Fatal(err)
	}
	if denied := a.Authorizer.Authorize(ctx, authorization.Request{Action: "s3:GetObject", ResourceARN: exact}); denied == nil {
		t.Fatal("existing session retained replaced source grant")
	}
	if denied := a.Authorizer.Authorize(ctx, authorization.Request{Action: "s3:GetObject", ResourceARN: "arn:aws:s3:::bucket/replacement.txt"}); denied != nil {
		t.Fatal(denied)
	}
	if err := a.DeletePolicy(f.ctx, list); err != nil {
		t.Fatal(err)
	}
	if denied := a.Authorizer.Authorize(ctx, authorization.Request{Action: "s3:GetObject", ResourceARN: "arn:aws:s3:::bucket/replacement.txt"}); denied == nil {
		t.Fatal("existing session retained deleted policy grant")
	}
	for _, key := range []string{"literal*key", "literal?key", "${aws:username}"} {
		list.Location = "s3://bucket/" + url.PathEscape(key)
		if err := a.PutPolicy(f.ctx, list); err != nil {
			t.Fatal(err)
		}
		resource := "arn:aws:s3:::bucket/" + key
		if denied := a.Authorizer.Authorize(ctx, authorization.Request{Action: "s3:GetObject", ResourceARN: resource}); denied != nil {
			t.Fatalf("literal object key %q denied: %v", key, denied)
		}
		for _, neighbor := range []string{"literalXkey", "${aws:username}extra", f.user.UserName} {
			if denied := a.Authorizer.Authorize(ctx, authorization.Request{Action: "s3:GetObject", ResourceARN: "arn:aws:s3:::bucket/" + neighbor}); denied == nil {
				t.Fatalf("literal object %q authorized undeclared key %q", key, neighbor)
			}
		}
		if err := a.DeletePolicy(f.ctx, list); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGuardDutyIPListLocationBoundaries(t *testing.T) {
	for _, location := range []string{"https://s3.us-west-2.amazonaws.com/bucket/path/list%20one%2B.txt", "https://bucket.s3-us-west-2.amazonaws.com/path/list%20one%2B.txt", "s3://bucket/path/list%20one%2B.txt", "http://bucket.s3.amazonaws.com/path/list%20one+.txt"} {
		bucket, key, err := guardDutyListLocation(location)
		if err != nil || bucket != "bucket" || key != "path/list one+.txt" {
			t.Fatalf("%q => %q/%q %v", location, bucket, key, err)
		}
	}
	for _, location := range []string{"https://example.com/bucket/file", "https://bucket.s3.amazonaws.com.attacker.test/file", "https://user@bucket.s3.amazonaws.com/file", "s3://bucket/file?versionId=1", "s3://bucket/"} {
		if _, _, err := guardDutyListLocation(location); err == nil {
			t.Fatalf("unsafe location accepted: %s", location)
		}
	}
}
