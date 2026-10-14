package cloudformation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"stackd/internal/awswire"
)

func TestSecureDynamicReferenceAWSSelectorsAndPropertyRestrictions(t *testing.T) {
	version := strings.Repeat("a", 32)
	for _, body := range []string{
		"ssm:/parameter", "ssm:/parameter:7", "ssm-secure:/parameter", "ssm-secure:/parameter:7",
		"secretsmanager:secret", "secretsmanager:secret::::", "secretsmanager:secret:SecretString:password",
		"secretsmanager:secret:SecretString:password:AWSPREVIOUS", "secretsmanager:secret:SecretString:password::" + version,
		"secretsmanager:arn:aws:secretsmanager:us-east-1:123456789012:secret:secret-abcdef:SecretString:password::" + version,
	} {
		if _, err := parseDynamicReference(body); err != nil {
			t.Fatalf("AWS selector rejected %q: %v", body, err)
		}
	}
	for _, body := range []string{
		"ssm-secure:/parameter:0", "ssm-secure:/parameter:stable", "ssm-secure:arn:aws:ssm:us-east-1:123456789012:parameter/name",
		"secretsmanager:", "secretsmanager:secret:SecretBinary", "secretsmanager:secret:SecretString:password:AWSCURRENT:" + version,
		"secretsmanager:secret:SecretString:password::short", "secretsmanager:secret:::::extra", "secretsmanager:secret\\",
	} {
		if _, err := parseDynamicReference(body); err == nil {
			t.Fatalf("invalid selector accepted %q", body)
		}
	}
	secure := "{{resolve:ssm-secure:/password}}"
	secret := "{{resolve:secretsmanager:password}}"
	for _, tc := range []struct {
		kind       string
		properties Properties
	}{
		{"AWS::IAM::User", Properties{"LoginProfile": map[string]any{"Password": secure}}},
		{"AWS::RDS::DBInstance", Properties{"MasterUserPassword": secure}},
		{"AWS::OpsWorks::Stack", Properties{"RdsDbInstances": []any{map[string]any{"DbPassword": secure}}}},
		{"AWS::Cognito::UserPoolIdentityProvider", Properties{"ProviderDetails": map[string]any{"client_secret": secret}}},
	} {
		if err := validateDynamicResourceProperties(tc.kind, tc.properties); err != nil {
			t.Fatalf("supported property rejected: %s: %v", tc.kind, err)
		}
	}
	for _, tc := range []struct {
		kind       string
		properties Properties
		code       string
	}{
		{"AWS::IAM::User", Properties{"UserName": secure}, "ValidationError"},
		{"AWS::Cognito::UserPoolIdentityProvider", Properties{"ProviderDetails": map[string]any{"client_secret": secure}}, "ValidationError"},
		{"AWS::EC2::Instance", Properties{"UserData": secret}, "ValidationError"},
		{"Custom::Resource", Properties{"Password": secret}, "ValidationError"},
		{"AWS::SSM::Parameter", Properties{"Name": secret}, "NotImplementedException"},
	} {
		var modeled *awswire.Error
		err := validateDynamicResourceProperties(tc.kind, tc.properties)
		if !errors.As(err, &modeled) || modeled.Code != tc.code {
			t.Fatalf("unsupported property lacks explicit boundary: %s: %v", tc.kind, err)
		}
	}
	var unsupported *awswire.Error
	err := validateDynamicResourceProperties("AWS::SSM::Parameter", Properties{"Value": secure})
	if !errors.As(err, &unsupported) || unsupported.Message != "SSM Secure reference is not supported in: [AWS::SSM::Parameter/Properties/Value]" {
		t.Fatalf("native unsupported secure SSM property diagnostic differs: %v", err)
	}
	if _, err := ParseTemplate(`{"Resources":{"User":{"Type":"AWS::IAM::User","Properties":{"LoginProfile":{"Password":{"Fn::Sub":"{{resolve:ssm-secure:/${Name}}}"}}}}},"Parameters":{"Name":{"Type":"String","Default":"password"}}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTemplate(`{"Resources":{"User":{"Type":"AWS::IAM::User","Properties":{"UserName":{"Fn::Sub":"{{resolve:ssm-secure:/${Name}}}"}}}},"Parameters":{"Name":{"Type":"String","Default":"password"}}}`); err == nil {
		t.Fatal("intrinsic secure reference bypassed property allowlist")
	}
}

func TestSecureDynamicReferenceRedactionPreservesModeledErrors(t *testing.T) {
	const secret = "password\n\"sensitive\""
	body, _ := json.Marshal(secret)
	cause := &awswire.Error{Code: "ValidationError", Message: "invalid " + string(body), Cause: errors.New(secret)}
	redacted := redactDynamicError(cause, []string{secret})
	var modeled *awswire.Error
	if !errors.As(redacted, &modeled) || modeled.Code != "ValidationError" || modeled.Cause != nil || strings.Contains(modeled.Message, "sensitive") {
		t.Fatalf("modeled error retained secret: %v", redacted)
	}
	pendingCause := &awswire.Error{Code: "OperationInProgressException", Cause: &ResourcePendingError{Reason: "busy " + secret}}
	pendingResult := redactDynamicError(pendingCause, []string{secret})
	var pending *ResourcePendingError
	if !errors.As(pendingResult, &pending) || strings.Contains(pending.Reason, secret) {
		t.Fatalf("redaction lost pending-admission semantics or exposed plaintext: %v", pendingResult)
	}
	properties := Properties{"LoginProfile": map[string]any{"Password": "{{resolve:ssm-secure:/password}}"}}
	original := ResourceResult{
		PhysicalID: "user", Ref: "user",
		Attributes: map[string]any{
			"Echo": secret, "Nested": map[string]any{"Values": []any{"prefix-" + secret}},
			"Arn": "arn:aws:iam::123456789012:user/user", "LiteralMask": "****", "AlreadyProtected": "****",
		},
		RedactedAttributes: map[string]bool{"AlreadyProtected": true},
	}
	safe, err := protectDynamicResult(original, []string{secret}, properties)
	if err != nil || safe.Attributes["Echo"] != "****" || original.Attributes["Echo"] != secret {
		t.Fatal("result redaction mutated the native owner or retained plaintext", err)
	}
	if !safe.RedactedAttributes["Echo"] || !safe.RedactedAttributes["Nested"] || !safe.RedactedAttributes["AlreadyProtected"] || safe.RedactedAttributes["Arn"] || safe.RedactedAttributes["LiteralMask"] || original.RedactedAttributes["Echo"] {
		t.Fatal("attribute redaction metadata was missing, overbroad, or mutated the native owner")
	}
	if original.Attributes["Nested"].(map[string]any)["Values"].([]any)[0] != "prefix-"+secret {
		t.Fatal("nested result redaction mutated the native owner")
	}
	if _, err := protectDynamicResult(ResourceResult{PhysicalID: secret}, []string{secret}, properties); err == nil {
		t.Fatal("secret identity could enter durable CFN metadata")
	}
	if err := rejectSecureDynamicOutsideProperties("{{resolve:secretsmanager:password}}", "Outputs.Password"); err == nil {
		t.Fatal("secure output path was silently accepted")
	}
}

func TestSecureDynamicReferenceSecretPinsAreOperationLocal(t *testing.T) {
	const secretReference = "{{resolve:secretsmanager:secret:SecretString:password:AWSPREVIOUS}}"
	const parameterReference = "{{resolve:ssm-secure:/password}}"
	pins := map[string]DynamicReferencePin{
		secretReference:    {Service: "secretsmanager", SecretVersionID: strings.Repeat("a", 32)},
		parameterReference: {Service: "ssm-secure", ParameterVersion: 7},
	}
	resource := ResourceRecord{Properties: Properties{"Password": secretReference}, DynamicReferences: pins}
	published := publishedDynamicResource(resource)
	if len(published.DynamicReferences) != 1 || published.DynamicReferences[parameterReference].ParameterVersion != 7 || len(resource.DynamicReferences) != 2 {
		t.Fatal("publication retained a deployment secret version or mutated the operation's pin")
	}
	step := StepRecord{Action: "UPDATE", Before: published}
	if !needsRollbackSecretResolution(&step) {
		t.Fatal("rollback reused an inferred prior-deployment secret version")
	}
	step.Before.DynamicReferences = pins
	if needsRollbackSecretResolution(&step) {
		t.Fatal("accepted rollback selection was not retained for replay")
	}
	op := OperationRecord{Phase: "DONE", Steps: []StepRecord{{Before: resource, After: resource, Restore: resource}}}
	forgetOperationSecretVersions(&op)
	for _, image := range []ResourceRecord{op.Steps[0].Before, op.Steps[0].After, op.Steps[0].Restore} {
		if len(image.DynamicReferences) != 1 || image.DynamicReferences[parameterReference].ParameterVersion != 7 {
			t.Fatal("completed operation tracked a prior deployment secret version or lost the SSM version")
		}
	}
}

func TestSecureDynamicReferenceNativeJSONCoercion(t *testing.T) {
	// Captured native AWS SSM String consumer values, 2026-10-14, using the
	// existing cloudformation_probe.py --secure-dynamic-references workflow.
	for _, tc := range []struct{ input, value string }{
		{`"public-two"`, "public-two"},
		{`42`, "42"},
		{`true`, "true"},
		{`{"nested": "public"}`, `{"nested":"public"}`},
		{`[1, "public"]`, `[1,"public"]`},
		{`null`, "null"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			value, err := dynamicSecretJSONValue(json.RawMessage(tc.input))
			if err != nil || value != tc.value {
				t.Fatalf("native JSON-key coercion: %q %v, want %q", value, err, tc.value)
			}
		})
	}
}

func TestSecureResultAttributeIntrinsicConsumption(t *testing.T) {
	result := ResourceResult{
		PhysicalID: "source", Ref: "source",
		Attributes:         map[string]any{"Value": "****", "Arn": "arn:source", "LiteralMask": "****"},
		RedactedAttributes: map[string]bool{"Value": true},
	}
	for _, expression := range []string{
		`{"Fn::GetAtt":["Source","Value"]}`,
		`{"Fn::GetAtt":"Source.Value"}`,
		`{"Fn::Sub":"${Source.Value}"}`,
		`{"Fn::Join":["",["prefix-",{"Fn::GetAtt":["Source","Value"]}]]}`,
	} {
		t.Run(expression, func(t *testing.T) {
			template, err := ParseTemplate(`{"Resources":{"Source":{"Type":"AWS::SSM::Parameter","Properties":{"Type":"String","Value":"source"}},"Consumer":{"Type":"AWS::SSM::Parameter","Properties":{"Type":"String","Value":` + expression + `}}},"Outputs":{"Consumed":{"Value":` + expression + `}}}`)
			if err != nil {
				t.Fatal(err)
			}
			input := Evaluation{Resources: map[string]ResourceResult{"Source": result}}
			_, err = template.ResolveResource("Consumer", input)
			assertSecureAttributeUnsupported(t, err)
			_, _, err = template.ResolveOutputs(input)
			assertSecureAttributeUnsupported(t, err)
			projected := template.evaluator(input)
			projected.eventProjection = true
			if _, err := projected.resolve(template.Outputs["Consumed"].Value); err != nil {
				t.Fatalf("event-only projection could not retain the mask: %v", err)
			}
		})
	}
	for _, attribute := range []string{"Arn", "LiteralMask"} {
		value, err := (&Template{}).evaluator(Evaluation{Resources: map[string]ResourceResult{"Source": result}}).attribute("Source", attribute)
		if err != nil || value != result.Attributes[attribute] {
			t.Fatalf("unmarked attribute %s was not consumable: %v %v", attribute, value, err)
		}
	}
}

func assertSecureAttributeUnsupported(t *testing.T, err error) {
	t.Helper()
	var wire *awswire.Error
	if !errors.As(err, &wire) || wire.Code != "NotImplementedException" || !strings.Contains(wire.Message, "stackd cannot consume secure resource attribute Source.Value") {
		t.Fatalf("secure attribute did not fail explicitly: %v", err)
	}
}

type secureAttributeResultReader struct {
	ResourceHandler
	result ResourceResult
}

func (r secureAttributeResultReader) Result(context.Context, ResourceRequest) (ResourceResult, error) {
	return r.result, nil
}

func TestSecureResultAttributeRefreshAndMemoryClones(t *testing.T) {
	prior := ResourceResult{
		PhysicalID: "source", Ref: "source",
		Attributes:         map[string]any{"Value": "****", "Arn": "arn:old"},
		RedactedAttributes: map[string]bool{"Value": true},
	}
	native := ResourceResult{
		PhysicalID: "source", Ref: "source",
		Attributes: map[string]any{"Value": "secret-plaintext", "Arn": "arn:new"},
	}
	refreshed, err := stabilizedResourceResult(t.Context(), secureAttributeResultReader{result: native}, ResourceRequest{PhysicalID: "source"}, prior)
	if err != nil || refreshed.Attributes["Value"] != "****" || !refreshed.RedactedAttributes["Value"] || refreshed.Attributes["Arn"] != "arn:new" {
		t.Fatalf("late refresh lost the protected projection or safe attributes: %+v %v", refreshed, err)
	}
	if native.Attributes["Value"] != "secret-plaintext" || native.RedactedAttributes != nil {
		t.Fatal("refresh protection mutated the native result")
	}
	record := ResourceRecord{Attributes: prior.Attributes, RedactedAttributes: prior.RedactedAttributes}
	cloned := cloneResource(record)
	cloned.RedactedAttributes["Value"] = false
	if !record.RedactedAttributes["Value"] {
		t.Fatal("resource metadata shared memory with a reader")
	}
	operation := cloneOperation(OperationRecord{Steps: []StepRecord{{Before: record, After: record, Restore: record}}})
	operation.Steps[0].Before.RedactedAttributes["Value"] = false
	operation.Steps[0].After.RedactedAttributes["Value"] = false
	operation.Steps[0].Restore.RedactedAttributes["Value"] = false
	if !record.RedactedAttributes["Value"] {
		t.Fatal("retained step metadata shared memory with a reader")
	}
}
