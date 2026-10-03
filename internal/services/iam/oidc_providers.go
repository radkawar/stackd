package iam

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

const maxOIDCProviders = 100

func oidcURL(raw string) (string, *awswire.Error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || (parsed.Port() != "" && parsed.Port() != "443") {
		return "", invalidInput("Unknown")
	}
	if strings.ContainsAny(parsed.Hostname(), " \t\r\n") || strings.Contains(parsed.Hostname(), ":") {
		return "", invalidInput("Unknown")
	}
	return parsed.Hostname() + parsed.EscapedPath(), nil
}
func oidcThumbprints(values []string) ([]string, *awswire.Error) {
	if len(values) == 0 {
		return nil, invalidInput("Thumbprint list must contain at least one entry.")
	}
	if len(values) > 5 {
		return nil, invalidInput("Thumbprint list must contain fewer than 5 entries.")
	}
	result := make([]string, len(values))
	for i, value := range values {
		if utf8.RuneCountInString(value) != 40 {
			return nil, invalid("Thumbprints must contain exactly 40 characters.")
		}
		result[i] = strings.ToLower(value)
	}
	return result, nil
}
func findOIDCProvider(a *account, arn string) (*OIDCProviderRecord, *awswire.Error) {
	if arn == "" {
		return nil, invalid("OpenIDConnectProviderArn is required.")
	}
	p := a.oidcProviders[arn]
	if p == nil {
		return nil, missing("OpenID Connect provider", arn)
	}
	return p, nil
}
func (s *Service) createOIDCProvider(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.CreateOpenIDConnectProviderInput](ctx)
	if err != nil {
		return nil, err
	}
	issuer, err := oidcURL(inputString(in.Url))
	if err != nil {
		return nil, err
	}
	arn := "arn:" + m.Partition + ":iam::" + m.AccountID + ":oidc-provider/" + issuer
	if a.oidcProviders[arn] != nil {
		return nil, duplicate("OpenID Connect provider", issuer)
	}
	if len(a.oidcProviders) >= maxOIDCProviders {
		return nil, limit("OpenID Connect provider quota exceeded.")
	}
	clients := make([]string, 0, len(in.ClientIDList))
	for _, value := range in.ClientIDList {
		client := string(value)
		if client == "" || utf8.RuneCountInString(client) > 255 {
			return nil, invalid("Client IDs must contain 1-255 characters.")
		}
		if !slices.Contains(clients, client) {
			clients = append(clients, client)
		}
	}
	if len(clients) > 100 {
		return nil, limit("Cannot exceed 100 client IDs per OpenID Connect provider.")
	}
	thumbprints := make([]string, len(in.ThumbprintList))
	for i, value := range in.ThumbprintList {
		thumbprints[i] = string(value)
	}
	if len(thumbprints) == 0 {
		thumbprints, _ = ctx.Value(preparedOIDCKey{}).([]string)
	}
	thumbprints, err = oidcThumbprints(thumbprints)
	if err != nil {
		return nil, err
	}
	tags, err := inputTags(in.Tags, "FederationProvider")
	if err != nil {
		return nil, err
	}
	a.oidcProviders[arn] = &OIDCProviderRecord{ARN: arn, ID: newID("AOID"), URL: issuer, CreatedAt: a.currentTime, ClientIDs: clients, Thumbprints: thumbprints, Tags: tags}
	return &iamapi.CreateOpenIDConnectProviderOutput{OpenIDConnectProviderArn: wirePointer(iamapi.ArnType(arn)), Tags: cloneFederationWireTags(in.Tags)}, nil
}
func getOIDCProvider(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.GetOpenIDConnectProviderInput](ctx)
	if err != nil {
		return nil, err
	}
	p, err := findOIDCProvider(a, inputString(in.OpenIDConnectProviderArn))
	if err != nil {
		return nil, err
	}
	clients := make(iamapi.ClientIDListType, len(p.ClientIDs))
	for i, value := range p.ClientIDs {
		clients[i] = iamapi.ClientIDType(value)
	}
	thumbprints := make(iamapi.ThumbprintListType, len(p.Thumbprints))
	for i, value := range p.Thumbprints {
		thumbprints[i] = iamapi.ThumbprintType(value)
	}
	return &iamapi.GetOpenIDConnectProviderOutput{Url: wirePointer(iamapi.OpenIDConnectProviderUrlType(p.URL)), CreateDate: wirePointer(iamapi.DateType(p.CreatedAt)), ClientIDList: clients, ThumbprintList: thumbprints, Tags: federationWireTags(p.Tags)}, nil
}
func listOIDCProviders(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	arns := make([]string, 0, len(a.oidcProviders))
	for arn := range a.oidcProviders {
		arns = append(arns, arn)
	}
	slices.Sort(arns)
	items := make(iamapi.OpenIDConnectProviderListType, len(arns))
	for i, arn := range arns {
		items[i] = iamapi.OpenIDConnectProviderListEntry{Arn: wirePointer(iamapi.ArnType(arn))}
	}
	return &iamapi.ListOpenIDConnectProvidersOutput{OpenIDConnectProviderList: items}, nil
}
func deleteOIDCProvider(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.DeleteOpenIDConnectProviderInput](ctx)
	if err != nil {
		return nil, err
	}
	p, err := findOIDCProvider(a, inputString(in.OpenIDConnectProviderArn))
	if err != nil {
		return nil, err
	}
	delete(a.oidcProviders, p.ARN)
	return &iamapi.DeleteOpenIDConnectProviderOutput{}, nil
}
func addOIDCClientID(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.AddClientIDToOpenIDConnectProviderInput](ctx)
	if err != nil {
		return nil, err
	}
	p, err := findOIDCProvider(a, inputString(in.OpenIDConnectProviderArn))
	if err != nil {
		return nil, err
	}
	client := inputString(in.ClientID)
	if slices.Contains(p.ClientIDs, client) {
		return &iamapi.AddClientIDToOpenIDConnectProviderOutput{}, nil
	}
	if len(p.ClientIDs) >= 100 {
		return nil, limit("Cannot exceed 100 client IDs per OpenID Connect provider.")
	}
	p.ClientIDs = append(p.ClientIDs, client)
	return &iamapi.AddClientIDToOpenIDConnectProviderOutput{}, nil
}
func removeOIDCClientID(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.RemoveClientIDFromOpenIDConnectProviderInput](ctx)
	if err != nil {
		return nil, err
	}
	p, err := findOIDCProvider(a, inputString(in.OpenIDConnectProviderArn))
	if err != nil {
		return nil, err
	}
	p.ClientIDs = slices.DeleteFunc(p.ClientIDs, func(value string) bool { return value == inputString(in.ClientID) })
	return &iamapi.RemoveClientIDFromOpenIDConnectProviderOutput{}, nil
}
func updateOIDCThumbprints(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.UpdateOpenIDConnectProviderThumbprintInput](ctx)
	if err != nil {
		return nil, err
	}
	p, err := findOIDCProvider(a, inputString(in.OpenIDConnectProviderArn))
	if err != nil {
		return nil, err
	}
	values := make([]string, len(in.ThumbprintList))
	for i, value := range in.ThumbprintList {
		values[i] = string(value)
	}
	values, err = oidcThumbprints(values)
	if err != nil {
		return nil, err
	}
	p.Thumbprints = values
	return &iamapi.UpdateOpenIDConnectProviderThumbprintOutput{}, nil
}
