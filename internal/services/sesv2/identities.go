package sesv2

import (
	"errors"
	api "stackd/internal/awsapi/sesv2"
	"strings"
	"time"
)

func (s *Service) registerControls() {
	register(s, "CreateEmailIdentity", s.createEmailIdentity)
	register(s, "GetEmailIdentity", s.getEmailIdentity)
	register(s, "ListEmailIdentities", s.listEmailIdentities)
	register(s, "DeleteEmailIdentity", s.deleteEmailIdentity)
	register(s, "PutEmailIdentityConfigurationSetAttributes", s.putIdentityConfiguration)
	register(s, "CreateConfigurationSet", s.createConfigurationSet)
	register(s, "GetConfigurationSet", s.getConfigurationSet)
	register(s, "ListConfigurationSets", s.listConfigurationSets)
	register(s, "DeleteConfigurationSet", s.deleteConfigurationSet)
	register(s, "PutConfigurationSetSendingOptions", s.putConfigurationSending)
	register(s, "CreateEmailTemplate", s.createTemplate)
	register(s, "UpdateEmailTemplate", s.updateTemplate)
	register(s, "GetEmailTemplate", s.getTemplate)
	register(s, "DeleteEmailTemplate", s.deleteTemplate)
	register(s, "ListEmailTemplates", s.listTemplates)
	register(s, "TestRenderEmailTemplate", s.testRenderTemplate)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTagsForResource", s.listTags)
	register(s, "GetAccount", s.getAccount)
	register(s, "PutAccountSendingAttributes", s.putAccountSending)
}
func (s *Service) createEmailIdentity(tx Transaction, in *api.CreateEmailIdentityInput) (*api.CreateEmailIdentityOutput, error) {
	name := value(in.EmailIdentity)
	if !strings.Contains(name, "@") {
		return nil, unsupported("Domain identity verification requires DNS/DKIM support; use an email identity and complete its captured verification link.")
	}
	address, e := parseAddress(name)
	if e != nil || address.Address != name {
		return nil, bad("Invalid email identity.")
	}
	if in.DkimSigningAttributes != nil {
		return nil, unsupported("DKIM signing attributes are not implemented.")
	}
	k := ResourceKey{scopeFor(tx.Context()), name}
	tags, e := parseTags(in.Tags)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "CreateEmailIdentity", k.ARN("identity"), nil, tagConditions(tags)); e != nil {
		return nil, e
	}
	if _, e = tx.Identity(k); e == nil {
		return nil, failure("AlreadyExistsException", "Email identity already exists.", 400)
	} else if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	config := value(in.ConfigurationSetName)
	if config != "" {
		if _, e = tx.ConfigurationSet(ResourceKey{k.Scope, config}); e != nil {
			return nil, e
		}
	}
	id := Identity{Key: k, ConfigurationSet: config, Tags: tags, Owner: cloudFormationOwner(tx.Context())}
	if e = s.verifyEmailIdentity(tx, id); e != nil {
		return nil, e
	}
	return &api.CreateEmailIdentityOutput{IdentityType: new(api.IdentityTypeEMAIL_ADDRESS), VerifiedForSendingStatus: new(api.Enabled(false))}, nil
}

func (s *Service) verifyEmailIdentity(tx Transaction, id Identity) error {
	if s.publicEndpoint == "" {
		return unsupported("Email identity verification requires the configured public endpoint.")
	}
	token, e := newID()
	if e != nil {
		return e
	}
	id.VerificationToken = token
	id.VerificationExpires = s.clock.Now().Add(24 * time.Hour)
	if e = tx.PutIdentity(id); e != nil {
		return e
	}
	_, e = s.acceptManaged(tx, id.Key.Scope, "no-reply-aws@amazon.com", id.Key.Name, "Amazon SES Email Address Verification Request", "To verify this email identity, open the following one-use link within 24 hours:\n\n"+s.verificationURL(token)+"\n", "SES_VERIFICATION")
	return e
}
func (s *Service) getEmailIdentity(tx Transaction, in *api.GetEmailIdentityInput) (*api.GetEmailIdentityOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.EmailIdentity)}
	id, e := tx.Identity(k)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "GetEmailIdentity", k.ARN("identity"), id.Tags, nil); e != nil {
		return nil, e
	}
	if e = observeCloudFormationResource(tx.Context(), k.ARN("identity"), id.Owner); e != nil {
		return nil, e
	}
	status := api.VerificationStatusPENDING
	if id.Verified {
		status = api.VerificationStatusSUCCESS
	} else if !s.clock.Now().Before(id.VerificationExpires) {
		status = api.VerificationStatusFAILED
	}
	out := &api.GetEmailIdentityOutput{IdentityType: new(api.IdentityTypeEMAIL_ADDRESS), VerifiedForSendingStatus: new(api.Enabled(id.Verified)), VerificationStatus: new(status), FeedbackForwardingStatus: new(api.Enabled(true)), Tags: apiTags(id.Tags)}
	if id.ConfigurationSet != "" {
		out.ConfigurationSetName = new(api.ConfigurationSetName(id.ConfigurationSet))
	}
	out.Policies, e = s.renderedIdentityPolicies(tx, id)
	if e != nil {
		return nil, e
	}
	return out, nil
}
func (s *Service) listEmailIdentities(tx Transaction, in *api.ListEmailIdentitiesInput) (*api.ListEmailIdentitiesOutput, error) {
	if e := s.authorize(tx, "ListEmailIdentities", "*", nil, nil); e != nil {
		return nil, e
	}
	rows, e := tx.Identities(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	start, end, next, e := page(rows, scopeFor(tx.Context()), "email-identities", "", in.NextToken, in.PageSize, func(v Identity) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.ListEmailIdentitiesOutput{EmailIdentities: api.IdentityInfoList{}, NextToken: next}
	for _, v := range rows[start:end] {
		status := api.VerificationStatusPENDING
		if v.Verified {
			status = api.VerificationStatusSUCCESS
		} else if !s.clock.Now().Before(v.VerificationExpires) {
			status = api.VerificationStatusFAILED
		}
		out.EmailIdentities = append(out.EmailIdentities, api.IdentityInfo{IdentityName: new(api.Identity(v.Key.Name)), IdentityType: new(api.IdentityTypeEMAIL_ADDRESS), SendingEnabled: new(api.Enabled(v.Verified)), VerificationStatus: new(status)})
	}
	return out, nil
}
func (s *Service) deleteEmailIdentity(tx Transaction, in *api.DeleteEmailIdentityInput) (*api.DeleteEmailIdentityOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.EmailIdentity)}
	id, e := tx.Identity(k)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "DeleteEmailIdentity", k.ARN("identity"), id.Tags, nil); e != nil {
		return nil, e
	}
	if e = observeCloudFormationResource(tx.Context(), k.ARN("identity"), id.Owner); e != nil {
		return nil, e
	}
	return &api.DeleteEmailIdentityOutput{}, tx.DeleteIdentity(k)
}
func (s *Service) putIdentityConfiguration(tx Transaction, in *api.PutEmailIdentityConfigurationSetAttributesInput) (*api.PutEmailIdentityConfigurationSetAttributesOutput, error) {
	k := ResourceKey{scopeFor(tx.Context()), value(in.EmailIdentity)}
	id, e := tx.Identity(k)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "PutEmailIdentityConfigurationSetAttributes", k.ARN("identity"), id.Tags, nil); e != nil {
		return nil, e
	}
	if e = observeCloudFormationResource(tx.Context(), k.ARN("identity"), id.Owner); e != nil {
		return nil, e
	}
	id.ConfigurationSet = value(in.ConfigurationSetName)
	if id.ConfigurationSet != "" {
		if _, e = tx.ConfigurationSet(ResourceKey{k.Scope, id.ConfigurationSet}); e != nil {
			return nil, e
		}
	}
	return &api.PutEmailIdentityConfigurationSetAttributesOutput{}, tx.PutIdentity(id)
}
func (s *Service) getAccount(tx Transaction, in *api.GetAccountInput) (*api.GetAccountOutput, error) {
	if e := s.authorize(tx, "GetAccount", "*", nil, nil); e != nil {
		return nil, e
	}
	v, e := tx.Account(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	return &api.GetAccountOutput{ProductionAccessEnabled: new(api.Enabled(false)), SendingEnabled: new(api.Enabled(v.SendingEnabled)), EnforcementStatus: new(api.GeneralEnforcementStatus("HEALTHY"))}, nil
}
func (s *Service) putAccountSending(tx Transaction, in *api.PutAccountSendingAttributesInput) (*api.PutAccountSendingAttributesOutput, error) {
	if e := s.authorize(tx, "PutAccountSendingAttributes", "*", nil, nil); e != nil {
		return nil, e
	}
	if in.SendingEnabled == nil {
		return nil, bad("SendingEnabled is required.")
	}
	return &api.PutAccountSendingAttributesOutput{}, tx.PutAccount(Account{scopeFor(tx.Context()), bool(*in.SendingEnabled)})
}
