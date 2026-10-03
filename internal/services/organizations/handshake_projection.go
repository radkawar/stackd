package organizations

import (
	api "stackd/internal/awsapi/organizations"
	"strings"
)

func (i HandshakeRecord) api(partition string) *api.Handshake {
	if i.Action != "INVITE" {
		return i.featureAPI(partition)
	}
	organization := handshakeResource("ORGANIZATION", i.OrganizationID)
	organization.Resources = api.HandshakeResources{handshakeResource("MASTER_EMAIL", i.ManagementEmail), handshakeResource("MASTER_NAME", i.ManagementName), handshakeResource("ORGANIZATION_FEATURE_SET", i.FeatureSet)}
	resources := api.HandshakeResources{organization, handshakeResource(i.TargetType, i.Target)}
	if i.Notes != "" {
		resources = append(resources, handshakeResource("NOTES", i.Notes))
	}
	partyType, partyID := i.TargetType, i.Target
	if i.State == "ACCEPTED" && i.TargetAccountID != "" {
		partyType, partyID = "ACCOUNT", i.TargetAccountID
	}
	return &api.Handshake{Id: new(api.HandshakeId(i.ID)), Arn: new(api.HandshakeArn(i.arn(partition))), Action: new(api.ActionType("INVITE")), State: new(api.HandshakeState(i.State)), RequestedTimestamp: &i.RequestedAt, ExpirationTimestamp: &i.ExpiresAt, Resources: resources, Parties: api.HandshakeParties{
		{Id: new(api.HandshakePartyId(strings.TrimPrefix(i.OrganizationID, "o-"))), Type: new(api.HandshakePartyType("ORGANIZATION"))},
		{Id: new(api.HandshakePartyId(partyID)), Type: new(api.HandshakePartyType(partyType))},
	}}
}

func handshakeResource(kind, value string) api.HandshakeResource {
	return api.HandshakeResource{Type: new(api.HandshakeResourceType(kind)), Value: new(api.HandshakeResourceValue(value))}
}

func (i HandshakeRecord) featureAPI(partition string) *api.Handshake {
	resources := api.HandshakeResources{}
	if i.ParentID != "" {
		resources = append(resources, handshakeResource("PARENT_HANDSHAKE", strings.TrimPrefix(i.ParentID, "h-")))
	}
	resources = append(resources, handshakeResource("ORGANIZATION", i.OrganizationID))
	parties := api.HandshakeParties{{Id: new(api.HandshakePartyId(strings.TrimPrefix(i.OrganizationID, "o-"))), Type: new(api.HandshakePartyType("ORGANIZATION"))}}
	if i.TargetAccountID != "" {
		parties = append(parties, api.HandshakeParty{Id: new(api.HandshakePartyId(i.TargetAccountID)), Type: new(api.HandshakePartyType("ACCOUNT"))})
		resources = append(resources, handshakeResource("ACCOUNT", i.TargetAccountID))
	}
	return &api.Handshake{Id: new(api.HandshakeId(i.ID)), Arn: new(api.HandshakeArn(i.arn(partition))), Action: new(api.ActionType(i.Action)), State: new(api.HandshakeState(i.State)), RequestedTimestamp: &i.RequestedAt, ExpirationTimestamp: &i.ExpiresAt, Parties: parties, Resources: resources}
}
