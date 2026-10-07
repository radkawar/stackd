package integrations

import (
	"reflect"
	"testing"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/services/cloudformation"
)

func TestCFNCognitoSoftwareTokenFactorAtomicAndDurable(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNCognitoOwnerFixture(t, backend)
			request := cfnWorkflowOwnerRequest("AWS::Cognito::UserPool", "Pool", cloudformation.Properties{"UserPoolName": "mfa", "UsernameAttributes": []any{"email"}, "MfaConfiguration": "OPTIONAL", "EnabledMfas": []any{"SOFTWARE_TOKEN_MFA"}})
			h := cfnCognitoUserPool{f.commands}
			created, err := h.Create(f.ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			request.PhysicalID = created.PhysicalID
			f.restart(t)
			h = cfnCognitoUserPool{f.commands}
			recovered, err := h.RecoverCreation(f.ctx, request)
			if err != nil || recovered.PhysicalID != created.PhysicalID {
				t.Fatalf("recovery: %+v %v", recovered, err)
			}
			state, err := h.Read(f.ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if state["MfaConfiguration"] != "OPTIONAL" || !reflect.DeepEqual(state["EnabledMfas"], []any{"SOFTWARE_TOKEN_MFA"}) {
				t.Fatalf("MFA readback=%v", state)
			}
			config, err := cfnMessagingCall[api.GetUserPoolMfaConfigOutput](f.ctx, f.commands, "cognitoidp", "GetUserPoolMfaConfig", &api.GetUserPoolMfaConfigInput{UserPoolId: new(api.UserPoolIdType(created.PhysicalID))})
			if err != nil || config.SoftwareTokenMfaConfiguration == nil || config.SoftwareTokenMfaConfiguration.Enabled == nil || !bool(*config.SoftwareTokenMfaConfiguration.Enabled) {
				t.Fatalf("factor not effective: %+v %v", config, err)
			}
			request.Previous = request.Properties
			request.Properties = cloudformation.Properties{"UserPoolName": "mfa", "UsernameAttributes": []any{"email"}, "MfaConfiguration": "OFF", "EnabledMfas": []any{}}
			if _, err := h.Update(f.ctx, request); err != nil {
				t.Fatal(err)
			}
			f.restart(t)
			h = cfnCognitoUserPool{f.commands}
			state, err = h.Read(f.ctx, request)
			if err != nil || state["MfaConfiguration"] != "OFF" || !reflect.DeepEqual(state["EnabledMfas"], []any{}) {
				t.Fatalf("factor removal: %v %v", state, err)
			}
		})
	}
}

func TestCFNCognitoRejectsInertFactors(t *testing.T) {
	h := cfnCognitoUserPool{}
	for _, properties := range []cloudformation.Properties{
		{"UserPoolName": "bad", "MfaConfiguration": "ON"},
		{"UserPoolName": "bad", "EnabledMfas": []any{"SMS_MFA"}},
		{"UserPoolName": "bad", "EnabledMfas": []any{"SOFTWARE_TOKEN_MFA", "SOFTWARE_TOKEN_MFA"}},
		{"UserPoolName": "bad", "EnabledMfas": "SOFTWARE_TOKEN_MFA"},
	} {
		if err := h.Validate(properties); err == nil {
			t.Fatalf("invalid factor accepted: %v", properties)
		}
	}
}
