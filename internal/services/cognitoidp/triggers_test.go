package cognitoidp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type classicTriggerInvoker func(context.Context, PoolKey, string, []byte) ([]byte, error)

func (f classicTriggerInvoker) InvokeTrigger(ctx context.Context, pool PoolKey, function string, payload []byte) ([]byte, error) {
	return f(ctx, pool, function, payload)
}

type classicTriggerFixture struct {
	repository *MemoryRepository
	service    *Service
	ctx        context.Context
	pool       *api.UserPoolType
	client     *api.UserPoolClientType
}

func newClassicTriggerFixture(t *testing.T, invoker TriggerInvoker, emailUsername bool) *classicTriggerFixture {
	t.Helper()
	repository := NewMemoryRepository(nil)
	f := &classicTriggerFixture{repository: repository, service: New(Config{Repository: repository, TriggerInvoker: invoker}), ctx: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root"})}
	function := str[api.ArnType]("arn:aws:lambda:us-east-1:123456789012:function:classic-hook")
	input := &api.CreateUserPoolInput{PoolName: str[api.UserPoolNameType]("classic-triggers"), LambdaConfig: &api.LambdaConfigType{PreSignUp: function, PreAuthentication: function, PostConfirmation: function}}
	if emailUsername {
		input.UsernameAttributes = api.UsernameAttributesListType{"email"}
	}
	poolOut, rejected := f.call("CreateUserPool", input)
	if rejected != nil {
		t.Fatal(rejected)
	}
	f.pool = poolOut.(*api.CreateUserPoolOutput).UserPool
	clientOut, rejected := f.call("CreateUserPoolClient", &api.CreateUserPoolClientInput{UserPoolId: f.pool.Id, ClientName: str[api.ClientNameType]("classic-client"), ExplicitAuthFlows: api.ExplicitAuthFlowsListType{"ALLOW_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH"}, PreventUserExistenceErrors: str[api.PreventUserExistenceErrorTypes]("ENABLED")})
	if rejected != nil {
		t.Fatal(rejected)
	}
	f.client = clientOut.(*api.CreateUserPoolClientOutput).UserPoolClient
	return f
}
func (f *classicTriggerFixture) call(action string, input any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("cognitoidp")
	op, _ := model.Operation(action)
	return f.service.ExecuteCommand(f.ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
}
func classicTriggerResponse(t *testing.T, payload []byte, response any) []byte {
	t.Helper()
	var event map[string]any
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	event["response"] = response
	out, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func classicSignUp(f *classicTriggerFixture, username string) (any, *awswire.Error) {
	return f.call("SignUp", &api.SignUpInput{ClientId: f.client.ClientId, Username: str[api.UsernameType](username), Password: str[api.PasswordType]("Password123!"), UserAttributes: api.AttributeListType{{Name: str[api.AttributeNameType]("email"), Value: str[api.AttributeValueType]("alice@example.invalid")}}, ClientMetadata: api.ClientMetadataType{"tenant": "one"}, ValidationData: api.AttributeListType{{Name: str[api.AttributeNameType]("invite"), Value: str[api.AttributeValueType]("accepted")}}})
}
func TestClassicTriggersAutoConfirmStableEmailUsernameAndPostCommit(t *testing.T) {
	var f *classicTriggerFixture
	var username string
	calls := 0
	invoker := classicTriggerInvoker(func(ctx context.Context, pool PoolKey, function string, payload []byte) ([]byte, error) {
		var event triggerEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			t.Fatal(err)
		}
		calls++
		if event.TriggerSource == "PreSignUp_SignUp" {
			username = event.UserName
			if event.Request.ValidationData["invite"] != "accepted" || event.Request.ClientMetadata["tenant"] != "one" {
				t.Fatalf("missing metadata: %+v", event.Request)
			}
			if err := f.repository.View(ctx, func(r Reader) error {
				_, err := r.User(UserKey{PoolKey: pool, Username: username})
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("pre-signup already committed user: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			return classicTriggerResponse(t, payload, preSignUpResponse{AutoConfirmUser: true, AutoVerifyEmail: true}), nil
		}
		if event.TriggerSource != "PostConfirmation_ConfirmSignUp" {
			t.Fatalf("unexpected trigger: %s", event.TriggerSource)
		}
		if event.UserName != username {
			t.Fatalf("random username changed across preflight: %s -> %s", username, event.UserName)
		}
		if err := f.repository.View(ctx, func(r Reader) error {
			user, err := r.User(UserKey{PoolKey: pool, Username: username})
			if err != nil {
				return err
			}
			if value(user.Data.UserStatus) != "CONFIRMED" || userAttribute(user, "email_verified") != "true" {
				t.Fatalf("post-confirmation ran before commit: %+v", user.Data)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return nil, failure("UserLambdaValidationException", "post-confirmation failed")
	})
	f = newClassicTriggerFixture(t, invoker, true)
	_, rejected := classicSignUp(f, "alice@example.invalid")
	if rejected == nil || rejected.Code != "UserLambdaValidationException" || calls != 2 {
		t.Fatalf("post-confirmation result=%v calls=%d", rejected, calls)
	}
	out, rejected := f.call("AdminGetUser", &api.AdminGetUserInput{UserPoolId: f.pool.Id, Username: str[api.UsernameType]("alice@example.invalid")})
	if rejected != nil || value(out.(*api.AdminGetUserOutput).UserStatus) != "CONFIRMED" {
		t.Fatalf("post-confirmation failure rolled back confirmation: %v", rejected)
	}
}
func TestClassicTriggerDenialAndMalformedResponseNeverCreateAccount(t *testing.T) {
	for _, test := range []struct {
		name, code string
		invoke     classicTriggerInvoker
	}{
		{"denied", "UserLambdaValidationException", func(context.Context, PoolKey, string, []byte) ([]byte, error) {
			return nil, failure("UserLambdaValidationException", "invitation denied")
		}},
		{"malformed", "InvalidLambdaResponseException", func(context.Context, PoolKey, string, []byte) ([]byte, error) {
			return []byte(`{"statusCode":200,"body":"allowed"}`), nil
		}},
		{"missing-email", "InvalidParameterException", func(ctx context.Context, pool PoolKey, function string, payload []byte) ([]byte, error) {
			return classicTriggerResponse(t, payload, preSignUpResponse{AutoVerifyPhone: true}), nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newClassicTriggerFixture(t, test.invoke, false)
			_, rejected := classicSignUp(f, "alice")
			if rejected == nil || rejected.Code != test.code {
				t.Fatalf("trigger rejection=%v", rejected)
			}
			_, rejected = f.call("AdminGetUser", &api.AdminGetUserInput{UserPoolId: f.pool.Id, Username: str[api.UsernameType]("alice")})
			if rejected == nil || rejected.Code != "UserNotFoundException" {
				t.Fatalf("rejected signup created account: %v", rejected)
			}
		})
	}
}
func TestPreAuthenticationDenialAndConcurrentDisable(t *testing.T) {
	for _, concurrentDisable := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "disabled-during-invoke"}[concurrentDisable], func(t *testing.T) {
			var f *classicTriggerFixture
			invoker := classicTriggerInvoker(func(ctx context.Context, pool PoolKey, function string, payload []byte) ([]byte, error) {
				var event triggerEvent
				if err := json.Unmarshal(payload, &event); err != nil {
					t.Fatal(err)
				}
				if event.TriggerSource == "PreSignUp_SignUp" {
					return classicTriggerResponse(t, payload, preSignUpResponse{AutoConfirmUser: true}), nil
				}
				if event.TriggerSource == "PostConfirmation_ConfirmSignUp" {
					return classicTriggerResponse(t, payload, struct{}{}), nil
				}
				if event.TriggerSource != "PreAuthentication_Authentication" || event.Request.ValidationData["risk"] != "high" || event.Request.UserNotFound == nil || *event.Request.UserNotFound {
					t.Fatalf("incorrect preauth event: %+v", event)
				}
				if !concurrentDisable {
					return nil, failure("UserLambdaValidationException", "risk denied")
				}
				if err := f.repository.Update(ctx, func(tx Transaction) error {
					user, err := tx.User(UserKey{PoolKey: pool, Username: event.UserName})
					if err != nil {
						return err
					}
					user.Data.Enabled = ptr(api.BooleanType(false))
					return tx.PutUser(user)
				}); err != nil {
					t.Fatal(err)
				}
				return classicTriggerResponse(t, payload, struct{}{}), nil
			})
			f = newClassicTriggerFixture(t, invoker, false)
			if _, rejected := classicSignUp(f, "alice"); rejected != nil {
				t.Fatal(rejected)
			}
			_, rejected := f.call("InitiateAuth", &api.InitiateAuthInput{ClientId: f.client.ClientId, AuthFlow: str[api.AuthFlowType]("USER_PASSWORD_AUTH"), AuthParameters: api.AuthParametersType{"USERNAME": "alice", "PASSWORD": "Password123!"}, ClientMetadata: api.ClientMetadataType{"risk": "high"}})
			code := "UserLambdaValidationException"
			if concurrentDisable {
				code = "NotAuthorizedException"
			}
			if rejected == nil || rejected.Code != code {
				t.Fatalf("authentication bypassed trigger/revalidation: error=%v", rejected)
			}
		})
	}
}
func TestAdminCreateUserIgnoresPreSignUpFlags(t *testing.T) {
	calls := 0
	f := newClassicTriggerFixture(t, classicTriggerInvoker(func(ctx context.Context, pool PoolKey, function string, payload []byte) ([]byte, error) {
		calls++
		var event triggerEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			t.Fatal(err)
		}
		if event.TriggerSource != "PreSignUp_AdminCreateUser" || event.CallerContext.ClientID != "CLIENT_ID_NOT_APPLICABLE" {
			t.Fatalf("admin event=%+v", event)
		}
		return classicTriggerResponse(t, payload, preSignUpResponse{AutoConfirmUser: true, AutoVerifyEmail: true, AutoVerifyPhone: true}), nil
	}), false)
	out, rejected := f.call("AdminCreateUser", &api.AdminCreateUserInput{UserPoolId: f.pool.Id, Username: str[api.UsernameType]("admin-user"), MessageAction: str[api.MessageActionType]("SUPPRESS"), TemporaryPassword: str[api.PasswordType]("Password123!")})
	if rejected != nil {
		t.Fatal(rejected)
	}
	if calls != 1 || value(out.(*api.AdminCreateUserOutput).User.UserStatus) != "FORCE_CHANGE_PASSWORD" {
		t.Fatalf("admin creation applied ignored flags: calls=%d out=%v", calls, out)
	}
}
func TestPreAuthenticationMissingUserAndSRPAttempt(t *testing.T) {
	for _, flow := range []string{"USER_PASSWORD_AUTH", "USER_SRP_AUTH"} {
		t.Run(flow, func(t *testing.T) {
			calls := 0
			f := newClassicTriggerFixture(t, classicTriggerInvoker(func(ctx context.Context, pool PoolKey, function string, payload []byte) ([]byte, error) {
				calls++
				var event triggerEvent
				if err := json.Unmarshal(payload, &event); err != nil {
					t.Fatal(err)
				}
				if event.TriggerSource != "PreAuthentication_Authentication" || event.UserName != "missing-user" || event.Request.UserNotFound == nil || !*event.Request.UserNotFound || event.Request.ValidationData["risk"] != "high" {
					t.Fatalf("missing-user preauth event=%+v", event)
				}
				return nil, failure("UserLambdaValidationException", "unknown-user denied")
			}), false)
			_, rejected := f.call("InitiateAuth", &api.InitiateAuthInput{ClientId: f.client.ClientId, AuthFlow: str[api.AuthFlowType](flow), AuthParameters: api.AuthParametersType{"USERNAME": "missing-user", "PASSWORD": "Password123!", "SRP_A": "2"}, ClientMetadata: api.ClientMetadataType{"risk": "high"}})
			if rejected == nil || rejected.Code != "UserLambdaValidationException" || calls != 1 {
				t.Fatalf("missing-user trigger bypassed: error=%v calls=%d", rejected, calls)
			}
		})
	}
}
