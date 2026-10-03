package sesv2

import (
	"errors"
	classic "stackd/internal/awsapi/ses"
	api "stackd/internal/awsapi/sesv2"
)

func (c *ClassicService) registerIdentities() {
	registerClassic(c, "VerifyEmailIdentity", c.verifyEmailIdentity)
	registerClassic(c, "VerifyEmailAddress", c.verifyEmailAddress)
	registerClassic(c, "ListIdentities", c.listIdentities)
	registerClassic(c, "ListVerifiedEmailAddresses", c.listVerifiedEmailAddresses)
	registerClassic(c, "DeleteIdentity", c.deleteIdentity)
	registerClassic(c, "DeleteVerifiedEmailAddress", c.deleteVerifiedEmailAddress)
	registerClassic(c, "GetIdentityVerificationAttributes", c.getIdentityVerificationAttributes)
	registerClassic(c, "PutIdentityPolicy", c.putIdentityPolicy)
	registerClassic(c, "GetIdentityPolicies", c.getIdentityPolicies)
	registerClassic(c, "ListIdentityPolicies", c.listIdentityPolicies)
	registerClassic(c, "DeleteIdentityPolicy", c.deleteIdentityPolicy)
	// TODO: Comeback — domain verification, DKIM, custom MAIL FROM and SNS
	// feedback controls require DNS/signing/notification consumers, not inert state.
}

func (c *ClassicService) verifyAddress(tx Transaction, name string) error {
	address, e := parseAddress(name)
	if e != nil || address.Address != name {
		return bad("Invalid email address.")
	}
	key := ResourceKey{scopeFor(tx.Context()), name}
	id, e := tx.Identity(key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if errors.Is(e, ErrNotFound) {
		id = Identity{Key: key}
	}
	if e = c.owner.authorize(tx, "VerifyEmailIdentity", key.ARN("identity"), id.Tags, nil); e != nil {
		return e
	}
	return c.owner.verifyEmailIdentity(tx, id)
}
func (c *ClassicService) verifyEmailIdentity(tx Transaction, in *classic.VerifyEmailIdentityInput) (*classic.VerifyEmailIdentityOutput, error) {
	return &classic.VerifyEmailIdentityOutput{}, c.verifyAddress(tx, value(in.EmailAddress))
}
func (c *ClassicService) verifyEmailAddress(tx Transaction, in *classic.VerifyEmailAddressInput) (*classic.VerifyEmailAddressOutput, error) {
	return &classic.VerifyEmailAddressOutput{}, c.verifyAddress(tx, value(in.EmailAddress))
}
func (c *ClassicService) deleteAddress(tx Transaction, name string) error {
	key := ResourceKey{scopeFor(tx.Context()), name}
	id, e := tx.Identity(key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if e = c.owner.authorize(tx, "DeleteIdentity", key.ARN("identity"), id.Tags, nil); e != nil {
		return e
	}
	return tx.DeleteIdentity(key)
}
func (c *ClassicService) deleteIdentity(tx Transaction, in *classic.DeleteIdentityInput) (*classic.DeleteIdentityOutput, error) {
	return &classic.DeleteIdentityOutput{}, c.deleteAddress(tx, value(in.Identity))
}
func (c *ClassicService) deleteVerifiedEmailAddress(tx Transaction, in *classic.DeleteVerifiedEmailAddressInput) (*classic.DeleteVerifiedEmailAddressOutput, error) {
	return &classic.DeleteVerifiedEmailAddressOutput{}, c.deleteAddress(tx, value(in.EmailAddress))
}
func (c *ClassicService) listIdentities(tx Transaction, in *classic.ListIdentitiesInput) (*classic.ListIdentitiesOutput, error) {
	if e := c.owner.authorize(tx, "ListIdentities", "*", nil, nil); e != nil {
		return nil, e
	}
	if in.IdentityType != nil && *in.IdentityType != classic.IdentityTypeEmailAddress && *in.IdentityType != classic.IdentityTypeDomain {
		return nil, bad("Invalid identity type.")
	}
	rows, e := tx.Identities(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	if in.IdentityType != nil && *in.IdentityType == classic.IdentityTypeDomain {
		rows = nil
	}
	start, end, next, e := page(rows, scopeFor(tx.Context()), "classic-identities", string(value(in.IdentityType)), (*api.NextToken)(in.NextToken), (*api.MaxItems)(in.MaxItems), func(id Identity) string { return id.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &classic.ListIdentitiesOutput{Identities: classic.IdentityList{}, NextToken: (*classic.NextToken)(next)}
	for _, id := range rows[start:end] {
		out.Identities = append(out.Identities, classic.Identity(id.Key.Name))
	}
	return out, nil
}
func (c *ClassicService) listVerifiedEmailAddresses(tx Transaction, _ *classic.ListVerifiedEmailAddressesInput) (*classic.ListVerifiedEmailAddressesOutput, error) {
	if e := c.owner.authorize(tx, "ListVerifiedEmailAddresses", "*", nil, nil); e != nil {
		return nil, e
	}
	rows, e := tx.Identities(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	out := &classic.ListVerifiedEmailAddressesOutput{VerifiedEmailAddresses: classic.AddressList{}}
	for _, id := range rows {
		if id.Verified {
			out.VerifiedEmailAddresses = append(out.VerifiedEmailAddresses, classic.Address(id.Key.Name))
		}
	}
	return out, nil
}
func (c *ClassicService) getIdentityVerificationAttributes(tx Transaction, in *classic.GetIdentityVerificationAttributesInput) (*classic.GetIdentityVerificationAttributesOutput, error) {
	out := &classic.GetIdentityVerificationAttributesOutput{VerificationAttributes: classic.VerificationAttributes{}}
	if len(in.Identities) == 0 {
		if e := c.owner.authorize(tx, "GetIdentityVerificationAttributes", "*", nil, nil); e != nil {
			return nil, e
		}
	}
	for _, name := range in.Identities {
		key := ResourceKey{scopeFor(tx.Context()), string(name)}
		id, e := tx.Identity(key)
		if e != nil && !errors.Is(e, ErrNotFound) {
			return nil, e
		}
		if authErr := c.owner.authorize(tx, "GetIdentityVerificationAttributes", key.ARN("identity"), id.Tags, nil); authErr != nil {
			return nil, authErr
		}
		if errors.Is(e, ErrNotFound) {
			continue
		}
		status := classic.VerificationStatusPending
		if id.Verified {
			status = classic.VerificationStatusSuccess
		} else if !c.owner.clock.Now().Before(id.VerificationExpires) {
			status = classic.VerificationStatusFailed
		}
		out.VerificationAttributes[name] = classic.IdentityVerificationAttributes{VerificationStatus: new(status)}
	}
	return out, nil
}
