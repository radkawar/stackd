package apigateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type cognitoTTLPolicies struct{ allow bool }

func (p *cognitoTTLPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	if !p.allow {
		return authorization.PolicySet{}, nil
	}
	return authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"apigateway:*","Resource":"*"}]}`}}}, nil
}

func TestCognitoTTLNativeControlReplayAndCurrentAuthority(t *testing.T) {
	content, err := os.ReadFile("testdata/cognito-ttl.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Observations []struct {
			Label     string          `json:"label"`
			Operation string          `json:"operation"`
			Input     json.RawMessage `json:"input"`
			Result    struct {
				Code   string         `json:"code"`
				Output api.Authorizer `json:"output"`
			} `json:"result"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Observations) != 12 {
		t.Fatalf("incomplete native control sequence: %d", len(fixture.Observations))
	}
	policies := &cognitoTTLPolicies{allow: true}
	s := New(Config{Authorizer: authorization.New(policies, nil)})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:user/authorizer", PrincipalID: "authorizer"})
	key := APIKey{Scope: scopeFor(ctx), ID: "native-api"}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutAPI(APIRecord{Key: key, Name: "native-cognito"}) }); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, row := range fixture.Observations {
		t.Run(row.Label, func(t *testing.T) {
			var out *api.Authorizer
			var callError error
			err := s.repository.Update(ctx, func(tx Transaction) error {
				switch row.Operation {
				case "CreateAuthorizer":
					var in api.CreateAuthorizerRequest
					if err := json.Unmarshal(row.Input, &in); err != nil {
						return err
					}
					out, callError = s.createAuthorizer(tx, &in)
					if callError == nil {
						ids[value(row.Result.Output.Id)] = value(out.Id)
					}
				case "GetAuthorizer":
					var in api.GetAuthorizerRequest
					if err := json.Unmarshal(row.Input, &in); err != nil {
						return err
					}
					in.AuthorizerId = ptr(ids[value(in.AuthorizerId)])
					out, callError = s.getAuthorizer(tx, &in)
				case "UpdateAuthorizer":
					var in api.UpdateAuthorizerRequest
					if err := json.Unmarshal(row.Input, &in); err != nil {
						return err
					}
					in.AuthorizerId = ptr(ids[value(in.AuthorizerId)])
					out, callError = s.updateAuthorizer(tx, &in)
				default:
					t.Fatalf("unexpected native operation %s", row.Operation)
				}
				return callError
			})
			if row.Result.Code != "Success" {
				var wire *awswire.Error
				if !errors.As(err, &wire) || wire.Code != row.Result.Code {
					t.Fatalf("native rejection=%s local=%v", row.Result.Code, err)
				}
				return
			}
			if err != nil || out == nil {
				t.Fatalf("native success local=%v", err)
			}
			if value(out.Name) != value(row.Result.Output.Name) || out.Type == nil || *out.Type != api.AuthorizerTypeCOGNITO_USER_POOLS {
				t.Fatalf("native control shape mismatch: %#v", out)
			}
			expected := row.Result.Output.AuthorizerResultTtlInSeconds
			actual := out.AuthorizerResultTtlInSeconds
			if (actual == nil) != (expected == nil) || actual != nil && *actual != *expected {
				t.Fatalf("TTL native=%v local=%v", expected, actual)
			}
		})
	}
	id := ids["native-omitted"]
	patch := &api.UpdateAuthorizerRequest{RestApiId: ptr(key.ID), AuthorizerId: ptr(id), PatchOperations: api.ListOfPatchOperation{{Op: new(api.Op("replace")), Path: ptr("/authorizerResultTtlInSeconds"), Value: ptr("0")}}}
	policies.allow = false
	if err := s.repository.Update(ctx, func(tx Transaction) error { _, err := s.updateAuthorizer(tx, patch); return err }); err == nil {
		t.Fatal("current IAM denial was bypassed by retained authorizer state")
	}
	policies.allow = true
	if err := s.repository.View(ctx, func(r Reader) error {
		row, err := r.Authorizer(AuthorizerKey{APIKey: key, AuthorizerID: id})
		if err != nil {
			return err
		}
		if row.CognitoTTLSeconds == nil || *row.CognitoTTLSeconds != 300 || row.LambdaAuthorizer != nil {
			t.Fatalf("denied/remove patch changed prior state or enabled Lambda caching: %#v", row)
		}
		*row.CognitoTTLSeconds = 0
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("abort Cognito TTL patch")
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := s.updateAuthorizer(tx, patch); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		row, err := r.Authorizer(AuthorizerKey{APIKey: key, AuthorizerID: id})
		if err != nil {
			return err
		}
		if row.CognitoTTLSeconds == nil || *row.CognitoTTLSeconds != 300 {
			t.Fatal("read alias or rolled-back patch leaked")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	foreign := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "222222222222", Region: "us-east-1", PrincipalARN: "arn:aws:iam::222222222222:root", PrincipalID: "222222222222"})
	if err := s.repository.Update(foreign, func(tx Transaction) error {
		_, err := s.getAuthorizer(tx, &api.GetAuthorizerRequest{RestApiId: ptr(key.ID), AuthorizerId: ptr(id)})
		return err
	}); err == nil {
		t.Fatal("Cognito TTL control row leaked across accounts")
	}
}
