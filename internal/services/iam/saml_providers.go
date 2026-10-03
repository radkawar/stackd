package iam

import (
	"context"
	"slices"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const maxSAMLProviders = 100

func findSAMLProvider(a *account, arn string) (*SAMLProviderRecord, *awswire.Error) {
	if arn == "" {
		return nil, invalid("SAMLProviderArn is required.")
	}
	p := a.samlProviders[arn]
	if p == nil {
		return nil, missing("SAML provider", arn)
	}
	return p, nil
}
func createSAMLProvider(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.CreateSAMLProviderInput](ctx)
	if err != nil {
		return nil, err
	}
	name := inputString(in.Name)
	arn := "arn:" + m.Partition + ":iam::" + m.AccountID + ":saml-provider/" + name
	if a.samlProviders[arn] != nil {
		return nil, duplicate("SAML provider", name)
	}
	if len(a.samlProviders) >= maxSAMLProviders {
		return nil, limit("SAML provider quota exceeded.")
	}
	document := inputString(in.SAMLMetadataDocument)
	issuers, err := parseSAMLMetadata(document)
	if err != nil {
		return nil, err
	}
	tags, err := inputTags(in.Tags, "FederationProvider")
	if err != nil {
		return nil, err
	}
	now := a.currentTime
	provider := SAMLProviderRecord{ARN: arn, Name: name, UUID: federationID("SAMLSP"), MetadataDocument: document, Issuers: issuers, CreatedAt: now, ValidUntil: now.AddDate(100, 0, 0), Tags: tags, AssertionEncryptionMode: "Allowed"}
	if in.AddPrivateKey != nil {
		der, err := parseSAMLPrivateKey(string(*in.AddPrivateKey))
		if err != nil {
			return nil, err
		}
		provider.PrivateKeys = append(provider.PrivateKeys, SAMLPrivateKeyRecord{ID: federationID("SAMLPK"), CreatedAt: now, PKCS8DER: der})
	}
	if in.AssertionEncryptionMode != nil {
		provider.AssertionEncryptionMode = string(*in.AssertionEncryptionMode)
	}
	if provider.AssertionEncryptionMode == "Required" && len(provider.PrivateKeys) == 0 {
		return nil, invalid("Unable to set assertion encryption mode to Required because no private key is provided.")
	}
	a.samlProviders[arn] = &provider
	return &iamapi.CreateSAMLProviderOutput{SAMLProviderArn: wirePointer(iamapi.ArnType(arn)), Tags: cloneFederationWireTags(in.Tags)}, nil
}
func getSAMLProvider(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.GetSAMLProviderInput](ctx)
	if err != nil {
		return nil, err
	}
	p, err := findSAMLProvider(a, inputString(in.SAMLProviderArn))
	if err != nil {
		return nil, err
	}
	keys := make(iamapi.PrivateKeyList, len(p.PrivateKeys))
	for i, key := range p.PrivateKeys {
		keys[i] = iamapi.SAMLPrivateKey{KeyId: wirePointer(iamapi.PrivateKeyIdType(key.ID)), Timestamp: wirePointer(iamapi.DateType(key.CreatedAt))}
	}
	return &iamapi.GetSAMLProviderOutput{SAMLProviderUUID: wirePointer(iamapi.PrivateKeyIdType(p.UUID)), CreateDate: wirePointer(iamapi.DateType(p.CreatedAt)), ValidUntil: wirePointer(iamapi.DateType(p.ValidUntil)), SAMLMetadataDocument: wirePointer(iamapi.SAMLMetadataDocumentType(p.MetadataDocument)), AssertionEncryptionMode: wirePointer(iamapi.AssertionEncryptionModeType(p.AssertionEncryptionMode)), PrivateKeyList: keys, Tags: federationWireTags(p.Tags)}, nil
}
func listSAMLProviders(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	arns := make([]string, 0, len(a.samlProviders))
	for arn := range a.samlProviders {
		arns = append(arns, arn)
	}
	slices.Sort(arns)
	items := make(iamapi.SAMLProviderListType, len(arns))
	for i, arn := range arns {
		p := a.samlProviders[arn]
		items[i] = iamapi.SAMLProviderListEntry{Arn: wirePointer(iamapi.ArnType(arn)), CreateDate: wirePointer(iamapi.DateType(p.CreatedAt)), ValidUntil: wirePointer(iamapi.DateType(p.ValidUntil))}
	}
	return &iamapi.ListSAMLProvidersOutput{SAMLProviderList: items}, nil
}
func deleteSAMLProvider(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.DeleteSAMLProviderInput](ctx)
	if err != nil {
		return nil, err
	}
	p, err := findSAMLProvider(a, inputString(in.SAMLProviderArn))
	if err != nil {
		return nil, err
	}
	delete(a.samlProviders, p.ARN)
	return &iamapi.DeleteSAMLProviderOutput{}, nil
}
func updateSAMLProvider(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UpdateSAMLProviderInput](ctx)
	if err != nil {
		return nil, err
	}
	p, err := findSAMLProvider(a, inputString(in.SAMLProviderArn))
	if err != nil {
		return nil, err
	}
	if in.SAMLMetadataDocument == nil && in.AddPrivateKey == nil && in.RemovePrivateKey == nil && in.AssertionEncryptionMode == nil {
		return nil, invalid("Unable to update identity provider. No updates are defined for metadata or encryption assertion.")
	}
	if in.AddPrivateKey != nil && in.RemovePrivateKey != nil {
		return nil, invalid("Unable to add and remove private keys in the same request. Set a value for only one of the two parameters.")
	}
	updated := cloneSAMLProvider(*p)
	if in.SAMLMetadataDocument != nil {
		issuers, err := parseSAMLMetadata(string(*in.SAMLMetadataDocument))
		if err != nil {
			return nil, err
		}
		updated.MetadataDocument = string(*in.SAMLMetadataDocument)
		updated.Issuers = issuers
		updated.ValidUntil = a.currentTime.AddDate(100, 0, 0)
	}
	if in.AddPrivateKey != nil {
		if len(updated.PrivateKeys) >= 2 {
			return nil, limit("Private key limit of 2 is reached.")
		}
		der, err := parseSAMLPrivateKey(string(*in.AddPrivateKey))
		if err != nil {
			return nil, err
		}
		updated.PrivateKeys = append(updated.PrivateKeys, SAMLPrivateKeyRecord{ID: federationID("SAMLPK"), CreatedAt: a.currentTime, PKCS8DER: der})
	}
	if in.AssertionEncryptionMode != nil {
		updated.AssertionEncryptionMode = string(*in.AssertionEncryptionMode)
	}
	if in.RemovePrivateKey != nil {
		id := string(*in.RemovePrivateKey)
		index := slices.IndexFunc(updated.PrivateKeys, func(key SAMLPrivateKeyRecord) bool { return key.ID == id })
		if index < 0 || (len(updated.PrivateKeys) == 1 && updated.AssertionEncryptionMode == "Required") {
			return nil, invalidInput("Failed to remove private key.")
		}
		updated.PrivateKeys = slices.Delete(updated.PrivateKeys, index, index+1)
	}
	if updated.AssertionEncryptionMode == "Required" && len(updated.PrivateKeys) == 0 {
		return nil, invalidInput("Failed to set assertion encryption mode to Required because no private key is present.")
	}
	*p = updated
	return &iamapi.UpdateSAMLProviderOutput{SAMLProviderArn: wirePointer(iamapi.ArnType(p.ARN))}, nil
}
