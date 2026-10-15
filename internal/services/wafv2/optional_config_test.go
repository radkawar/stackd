package wafv2

import (
	"context"
	"errors"
	"net/http"
	"testing"

	api "stackd/internal/awsapi/wafv2"
	"stackd/internal/awswire"
)

func TestEmptyCaptchaChallengeConfiguration(t *testing.T) {
	statement := api.Statement{ByteMatchStatement: &api.ByteMatchStatement{
		FieldToMatch:         &api.FieldToMatch{SingleHeader: &api.SingleHeader{Name: new(api.FieldToMatchData("x-fixture"))}},
		PositionalConstraint: new(api.PositionalConstraint("EXACTLY")), SearchString: api.SearchString("block"), TextTransformations: none(),
	}}
	definition := func() definitionInput {
		r := rule("blocked-header", 0, api.RuleAction{Block: &api.BlockAction{}}, statement)
		r.CaptchaConfig, r.ChallengeConfig = &api.CaptchaConfig{}, &api.ChallengeConfig{}
		return definitionInput{
			DefaultAction: &api.DefaultAction{Allow: &api.AllowAction{}}, Rules: api.Rules{r}, VisibilityConfig: visibility("acl"),
			CaptchaConfig: &api.CaptchaConfig{}, ChallengeConfig: &api.ChallengeConfig{},
		}
	}
	repo := NewMemoryRepository(nil)
	scope := Scope{"aws", "111122223333", "us-east-1"}
	if err := repo.View(context.Background(), func(reader Reader) error {
		_, _, _, err := admitDefinition(reader, scope, definition())
		return err
	}); err != nil {
		t.Fatalf("empty optional shapes rejected a normal block rule: %v", err)
	}
	f := newFixture(t, definition().Rules, *definition().DefaultAction, nil)
	if verdict := f.inspect(HTTPRequest{Header: http.Header{"X-Fixture": {"block"}}}); !verdict.Blocked {
		t.Fatalf("empty token settings changed block evaluation: %+v", verdict)
	}
	if verdict := f.inspect(HTTPRequest{Header: http.Header{"X-Fixture": {"allow"}}}); verdict.Blocked {
		t.Fatalf("empty token settings changed allow evaluation: %+v", verdict)
	}
	immunity := func() *api.ImmunityTimeProperty {
		return &api.ImmunityTimeProperty{ImmunityTime: new(api.TimeWindowSecond(300))}
	}
	for _, test := range []struct {
		name   string
		change func(*definitionInput)
	}{
		{"acl CAPTCHA setting", func(in *definitionInput) { in.CaptchaConfig.ImmunityTimeProperty = immunity() }},
		{"acl Challenge setting", func(in *definitionInput) { in.ChallengeConfig.ImmunityTimeProperty = immunity() }},
		{"rule CAPTCHA setting", func(in *definitionInput) { in.Rules[0].CaptchaConfig.ImmunityTimeProperty = immunity() }},
		{"rule Challenge setting", func(in *definitionInput) { in.Rules[0].ChallengeConfig.ImmunityTimeProperty = immunity() }},
		{"malformed CAPTCHA setting", func(in *definitionInput) { in.CaptchaConfig.ImmunityTimeProperty = &api.ImmunityTimeProperty{} }},
		{"CAPTCHA action", func(in *definitionInput) { in.Rules[0].Action = &api.RuleAction{Captcha: &api.CaptchaAction{}} }},
		{"Challenge action", func(in *definitionInput) { in.Rules[0].Action = &api.RuleAction{Challenge: &api.ChallengeAction{}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := definition()
			test.change(&in)
			err := repo.View(context.Background(), func(reader Reader) error {
				_, _, _, err := admitDefinition(reader, scope, in)
				return err
			})
			var wire *awswire.Error
			if !errors.As(err, &wire) || wire.Code != "WAFInvalidParameterException" {
				t.Fatalf("substantive unsupported token behavior was admitted: %v", err)
			}
		})
	}
}
