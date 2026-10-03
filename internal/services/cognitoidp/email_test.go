package cognitoidp

import (
	"context"
	"errors"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"testing"
)

type rejectedEmail struct{}

func (rejectedEmail) QueueEmail(context.Context, EmailMessage) error {
	return errors.New("mail acceptance rejected")
}
func TestEmailAcceptanceFailureRollsBackSignup(t *testing.T) {
	r := NewMemoryRepository(nil)
	s := New(Config{Repository: r, EmailSender: rejectedEmail{}})
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})
	model, _ := awscatalog.LookupService("cognitoidp")
	call := func(action string, in any) (any, *awswire.Error) {
		op, _ := model.Operation(action)
		return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
	}
	poolOut, e := call("CreateUserPool", &api.CreateUserPoolInput{PoolName: new(api.UserPoolNameType("delivery-failure")), AutoVerifiedAttributes: api.VerifiedAttributesListType{"email"}})
	if e != nil {
		t.Fatal(e)
	}
	pool := poolOut.(*api.CreateUserPoolOutput).UserPool
	clientOut, e := call("CreateUserPoolClient", &api.CreateUserPoolClientInput{UserPoolId: pool.Id, ClientName: new(api.ClientNameType("application"))})
	if e != nil {
		t.Fatal(e)
	}
	client := clientOut.(*api.CreateUserPoolClientOutput).UserPoolClient
	_, e = call("SignUp", &api.SignUpInput{ClientId: client.ClientId, Username: new(api.UsernameType("alice")), Password: new(api.PasswordType("Password123!")), UserAttributes: api.AttributeListType{{Name: new(api.AttributeNameType("email")), Value: new(api.AttributeValueType("alice@example.invalid"))}}})
	if e == nil || e.Code != "CodeDeliveryFailureException" {
		t.Fatalf("delivery failure=%v", e)
	}
	_, e = call("AdminGetUser", &api.AdminGetUserInput{UserPoolId: pool.Id, Username: new(api.UsernameType("alice"))})
	if e == nil || e.Code != "UserNotFoundException" {
		t.Fatalf("failed delivery committed user: %v", e)
	}
	key := PoolKey{Scope: Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: string(*pool.Id)}
	if err := r.View(t.Context(), func(r Reader) error {
		_, err := r.EmailCode(EmailCodeKey{UserKey: UserKey{PoolKey: key, Username: "alice"}, Kind: "SIGN_UP"})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("failed delivery committed code: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
