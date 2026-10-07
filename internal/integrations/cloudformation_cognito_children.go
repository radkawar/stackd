package integrations

import (
	"context"
	"fmt"

	api "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cognitoidp"
)

// Pool children are fenced by the owner's per-incarnation claims (see
// cognitoidp.WithResourceOwner). Every create, including a Cloud Control
// create, commits its claim. Physical IDs are the Cloud Control compound
// identifiers; Ref is the native child name or ID.

type cfnCognitoUserPoolClient struct{ commands StepFunctionsCommands }

var cfnCognitoClientKeys = []string{"UserPoolId", "ClientId"}

func (h cfnCognitoUserPoolClient) createInput(r cloudformation.ResourceRequest) (*api.CreateUserPoolClientInput, error) {
	m := cfnCognitoWithout(r.Properties, "ClientId", "ClientSecret", "Name")
	if _, ok := m["ClientName"]; !ok {
		m["ClientName"] = cfnComputeName(cloudformation.ResourceRequest{StackID: r.StackID, StackName: r.StackName, LogicalID: r.LogicalID, Token: r.Token}, "ClientName", 128)
	}
	return cfnCognitoInput[api.CreateUserPoolClientInput](m)
}

func (h cfnCognitoUserPoolClient) Validate(p cloudformation.Properties) error {
	if err := cfnComputeRequired(p, "UserPoolId"); err != nil {
		return err
	}
	_, err := h.createInput(cloudformation.ResourceRequest{Properties: p, StackName: "stack", LogicalID: "Client"})
	return err
}

func (h cfnCognitoUserPoolClient) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "UserPoolId", "GenerateSecret"), h.Validate(b)
}

func cfnCognitoClientResult(c *api.UserPoolClientType) cloudformation.ResourceResult {
	pool, id := cfnComputeValue(c.UserPoolId), cfnComputeValue(c.ClientId)
	attributes := map[string]any{"ClientId": id, "Name": cfnComputeValue(c.ClientName)}
	if secret := cfnComputeValue(c.ClientSecret); secret != "" {
		attributes["ClientSecret"] = secret
	}
	return cloudformation.ResourceResult{PhysicalID: pool + "|" + id, Ref: id, Attributes: attributes}
}

// create admits this incarnation's client, or with recover set only observes
// it. Client IDs are generated; the owner's private client-token claim
// replays the same client for a retried create of the same incarnation.
func (h cfnCognitoUserPoolClient) create(ctx context.Context, r cloudformation.ResourceRequest, recover bool) (cloudformation.ResourceResult, error) {
	in, err := h.createInput(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnCognitoClaimContext(ctx, r)
	if recover {
		ctx = cognitoidp.WithCreationRecovery(ctx, cfnCognitoOwner(r))
	}
	out, err := cfnMessagingCall[api.CreateUserPoolClientOutput](ctx, h.commands, "cognitoidp", "CreateUserPoolClient", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoClientResult(out.UserPoolClient), nil
}

func (h cfnCognitoUserPoolClient) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.create(ctx, r, false)
}

// RecoverCreation observes only the client claimed by this exact incarnation.
func (h cfnCognitoUserPoolClient) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.create(ctx, r, true)
}

func (h cfnCognitoUserPoolClient) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoClientKeys...)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	m := cfnCognitoWithout(r.Properties, "GenerateSecret", "ClientId", "ClientSecret", "Name")
	m["UserPoolId"], m["ClientId"] = ids[0], ids[1]
	in, err := cfnCognitoInput[api.UpdateUserPoolClientInput](m)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnMessagingCall[api.UpdateUserPoolClientOutput](cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "UpdateUserPoolClient", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoClientResult(out.UserPoolClient), nil
}

func (h cfnCognitoUserPoolClient) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoClientKeys...)
	if err != nil {
		return err
	}
	return cfnCognitoAbsent(cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "DeleteUserPoolClient", &api.DeleteUserPoolClientInput{UserPoolId: new(api.UserPoolIdType(ids[0])), ClientId: new(api.ClientIdType(ids[1]))}))
}

func (h cfnCognitoUserPoolClient) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoClientKeys...)
	if err != nil {
		return nil, err
	}
	out, err := cfnMessagingCall[api.DescribeUserPoolClientOutput](ctx, h.commands, "cognitoidp", "DescribeUserPoolClient", &api.DescribeUserPoolClientInput{UserPoolId: new(api.UserPoolIdType(ids[0])), ClientId: new(api.ClientIdType(ids[1]))})
	if err != nil {
		return nil, err
	}
	p, err := cfnCognitoProject(out.UserPoolClient, "UserPoolId", "ClientId", "ClientName", "ClientSecret", "ExplicitAuthFlows", "ReadAttributes", "WriteAttributes",
		"AuthSessionValidity", "RefreshTokenValidity", "AccessTokenValidity", "IdTokenValidity", "TokenValidityUnits", "RefreshTokenRotation", "AllowedOAuthFlows",
		"AllowedOAuthFlowsUserPoolClient", "AllowedOAuthScopes", "CallbackURLs", "DefaultRedirectURI", "LogoutURLs", "SupportedIdentityProviders",
		"PreventUserExistenceErrors", "EnableTokenRevocation", "EnablePropagateAdditionalUserContextData")
	if err != nil {
		return nil, err
	}
	p["Name"] = p["ClientName"]
	p["GenerateSecret"] = cfnComputeValue(out.UserPoolClient.ClientSecret) != ""
	return p, nil
}

func (h cfnCognitoUserPoolClient) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	pool, err := cfnCognitoParent(r, "UserPoolId")
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	token := ""
	for {
		page := map[string]any{"UserPoolId": pool, "MaxResults": 60}
		if token != "" {
			page["NextToken"] = token
		}
		in, err := cfnCognitoInput[api.ListUserPoolClientsInput](page)
		if err != nil {
			return nil, err
		}
		listed, err := cfnMessagingCall[api.ListUserPoolClientsOutput](ctx, h.commands, "cognitoidp", "ListUserPoolClients", in)
		if err != nil {
			return nil, err
		}
		for _, client := range listed.UserPoolClients {
			id := pool + "|" + cfnComputeValue(client.ClientId)
			p, err := h.Read(ctx, cloudformation.ResourceRequest{PhysicalID: id, Scope: r.Scope, CloudControl: true})
			if cfnCognitoMissing(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: p})
		}
		if token = cfnComputeValue(listed.NextToken); token == "" {
			return out, nil
		}
	}
}

// UserPoolDomain admits prefix domains only; custom domains have no owner.
type cfnCognitoUserPoolDomain struct{ commands StepFunctionsCommands }

var cfnCognitoDomainKeys = []string{"UserPoolId", "Domain"}

func (h cfnCognitoUserPoolDomain) Validate(p cloudformation.Properties) error {
	if err := cfnComputeRequired(p, "UserPoolId", "Domain"); err != nil {
		return err
	}
	_, err := cfnCognitoInput[api.CreateUserPoolDomainInput](p)
	return err
}

func (h cfnCognitoUserPoolDomain) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "UserPoolId", "Domain"), h.Validate(b)
}

func cfnCognitoDomainResult(pool, domain string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: pool + "|" + domain, Ref: domain, Attributes: map[string]any{}}
}

func (h cfnCognitoUserPoolDomain) create(ctx context.Context, r cloudformation.ResourceRequest, recover bool) (cloudformation.ResourceResult, error) {
	in, err := cfnCognitoInput[api.CreateUserPoolDomainInput](r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	ctx = cfnCognitoClaimContext(ctx, r)
	if recover {
		ctx = cognitoidp.WithCreationRecovery(ctx, cfnCognitoOwner(r))
	}
	if err := cfnMessagingExec(ctx, h.commands, "cognitoidp", "CreateUserPoolDomain", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoDomainResult(cfnComputeValue(in.UserPoolId), cfnComputeValue(in.Domain)), nil
}

func (h cfnCognitoUserPoolDomain) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.create(ctx, r, false)
}

// RecoverCreation observes the exact private domain claim without admitting a
// domain or treating a native duplicate error as evidence of ownership.
func (h cfnCognitoUserPoolDomain) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.create(ctx, r, true)
}

func (h cfnCognitoUserPoolDomain) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoDomainKeys...)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	m := cfnCognitoWithout(r.Properties)
	m["UserPoolId"], m["Domain"] = ids[0], ids[1]
	in, err := cfnCognitoInput[api.UpdateUserPoolDomainInput](m)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "UpdateUserPoolDomain", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoDomainResult(ids[0], ids[1]), nil
}

func (h cfnCognitoUserPoolDomain) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoDomainKeys...)
	if err != nil {
		return err
	}
	// The owner reports an absent domain as an invalid parameter; resolve it
	// by an owner read first so only a present domain is deleted.
	if _, err := h.Read(ctx, r); err != nil {
		return cfnCognitoAbsent(err)
	}
	return cfnCognitoAbsent(cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "DeleteUserPoolDomain", &api.DeleteUserPoolDomainInput{UserPoolId: new(api.UserPoolIdType(ids[0])), Domain: new(api.DomainType(ids[1]))}))
}

func (h cfnCognitoUserPoolDomain) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoDomainKeys...)
	if err != nil {
		return nil, err
	}
	out, err := cfnMessagingCall[api.DescribeUserPoolDomainOutput](ctx, h.commands, "cognitoidp", "DescribeUserPoolDomain", &api.DescribeUserPoolDomainInput{Domain: new(api.DomainType(ids[1]))})
	if err != nil {
		return nil, err
	}
	d := out.DomainDescription
	if d == nil || cfnComputeValue(d.UserPoolId) != ids[0] {
		return nil, cfnCognitoNotFound("user pool domain " + ids[1])
	}
	return cloudformation.Properties{"UserPoolId": ids[0], "Domain": ids[1]}, nil
}

func (h cfnCognitoUserPoolDomain) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	pool, err := cfnCognitoParent(r, "UserPoolId")
	if err != nil {
		return nil, err
	}
	described, _, err := cfnCognitoUserPool(h).describe(ctx, pool)
	if err != nil {
		return nil, err
	}
	domain := cfnComputeValue(described.Domain)
	if domain == "" {
		return nil, nil
	}
	return []cloudformation.ResourceDescription{{Identifier: pool + "|" + domain, Properties: cloudformation.Properties{"UserPoolId": pool, "Domain": domain}}}, nil
}

type cfnCognitoUserPoolUser struct{ commands StepFunctionsCommands }

var cfnCognitoUserKeys = []string{"UserPoolId", "Username"}

func (h cfnCognitoUserPoolUser) Validate(p cloudformation.Properties) error {
	// The owner requires a username; it does not generate one.
	if err := cfnComputeRequired(p, "UserPoolId", "Username"); err != nil {
		return err
	}
	_, err := cfnCognitoInput[api.AdminCreateUserInput](p)
	return err
}

// Every user property is create-only.
func (h cfnCognitoUserPoolUser) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "UserPoolId", "Username", "UserAttributes", "ValidationData", "ClientMetadata", "DesiredDeliveryMediums", "ForceAliasCreation", "MessageAction"), h.Validate(b)
}

func (h cfnCognitoUserPoolUser) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, err := cfnCognitoInput[api.AdminCreateUserInput](r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnMessagingCall[api.AdminCreateUserOutput](cfnCognitoClaimContext(ctx, r), h.commands, "cognitoidp", "AdminCreateUser", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnComputeValue(out.User.Username)
	return cloudformation.ResourceResult{PhysicalID: cfnComputeValue(in.UserPoolId) + "|" + name, Ref: name, Attributes: map[string]any{}}, nil
}

func (h cfnCognitoUserPoolUser) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if replace, err := h.Replacement(r.Previous, r.Properties); err != nil || replace {
		if err == nil {
			err = fmt.Errorf("user pool user update requires replacement")
		}
		return cloudformation.ResourceResult{}, err
	}
	ids, err := cfnCognitoIdentifier(r, cfnCognitoUserKeys...)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cloudformation.ResourceResult{PhysicalID: ids[0] + "|" + ids[1], Ref: ids[1], Attributes: map[string]any{}}, nil
}

func (h cfnCognitoUserPoolUser) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoUserKeys...)
	if err != nil {
		return err
	}
	return cfnCognitoAbsent(cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "AdminDeleteUser", &api.AdminDeleteUserInput{UserPoolId: new(api.UserPoolIdType(ids[0])), Username: new(api.UsernameType(ids[1]))}))
}

func (h cfnCognitoUserPoolUser) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoUserKeys...)
	if err != nil {
		return nil, err
	}
	out, err := cfnMessagingCall[api.AdminGetUserOutput](ctx, h.commands, "cognitoidp", "AdminGetUser", &api.AdminGetUserInput{UserPoolId: new(api.UserPoolIdType(ids[0])), Username: new(api.UsernameType(ids[1]))})
	if err != nil {
		return nil, err
	}
	p, err := cfnCognitoProject(out, "UserAttributes")
	if err != nil {
		return nil, err
	}
	p["UserPoolId"], p["Username"] = ids[0], cfnComputeValue(out.Username)
	return p, nil
}

func (h cfnCognitoUserPoolUser) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	pool, err := cfnCognitoParent(r, "UserPoolId")
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	token := ""
	for {
		page := map[string]any{"UserPoolId": pool, "Limit": 60}
		if token != "" {
			page["PaginationToken"] = token
		}
		in, err := cfnCognitoInput[api.ListUsersInput](page)
		if err != nil {
			return nil, err
		}
		listed, err := cfnMessagingCall[api.ListUsersOutput](ctx, h.commands, "cognitoidp", "ListUsers", in)
		if err != nil {
			return nil, err
		}
		for _, user := range listed.Users {
			name := cfnComputeValue(user.Username)
			p, err := cfnCognitoProject(user, "Attributes")
			if err != nil {
				return nil, err
			}
			p = cloudformation.Properties{"UserPoolId": pool, "Username": name, "UserAttributes": p["Attributes"]}
			out = append(out, cloudformation.ResourceDescription{Identifier: pool + "|" + name, Properties: p})
		}
		if token = cfnComputeValue(listed.PaginationToken); token == "" {
			return out, nil
		}
	}
}

type cfnCognitoUserPoolGroup struct{ commands StepFunctionsCommands }

var cfnCognitoGroupKeys = []string{"UserPoolId", "GroupName"}

func (h cfnCognitoUserPoolGroup) input(r cloudformation.ResourceRequest) (*api.CreateGroupInput, error) {
	m := cfnCognitoWithout(r.Properties)
	if _, ok := m["GroupName"]; !ok {
		m["GroupName"] = cfnComputeName(cloudformation.ResourceRequest{StackID: r.StackID, StackName: r.StackName, LogicalID: r.LogicalID, Token: r.Token}, "GroupName", 128)
	}
	return cfnCognitoInput[api.CreateGroupInput](m)
}

func (h cfnCognitoUserPoolGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeRequired(p, "UserPoolId"); err != nil {
		return err
	}
	_, err := h.input(cloudformation.ResourceRequest{Properties: p, StackName: "stack", LogicalID: "Group"})
	return err
}

func (h cfnCognitoUserPoolGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "UserPoolId", "GroupName"), h.Validate(b)
}

func cfnCognitoGroupResult(pool, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: pool + "|" + name, Ref: name, Attributes: map[string]any{}}
}

func (h cfnCognitoUserPoolGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, err := h.input(r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	out, err := cfnMessagingCall[api.CreateGroupOutput](cfnCognitoClaimContext(ctx, r), h.commands, "cognitoidp", "CreateGroup", in)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoGroupResult(cfnComputeValue(in.UserPoolId), cfnComputeValue(out.Group.GroupName)), nil
}

// The owner cannot clear a role or precedence; omitting them keeps them.
func (h cfnCognitoUserPoolGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoGroupKeys...)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	for _, key := range []string{"RoleArn", "Precedence", "Description"} {
		if _, before := r.Previous[key]; before {
			if _, after := r.Properties[key]; !after {
				return cloudformation.ResourceResult{}, fmt.Errorf("user pool group property %s cannot be removed; set a new value", key)
			}
		}
	}
	m := cfnCognitoWithout(r.Properties)
	m["UserPoolId"], m["GroupName"] = ids[0], ids[1]
	in, err := cfnCognitoInput[api.UpdateGroupInput](m)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "UpdateGroup", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoGroupResult(ids[0], ids[1]), nil
}

func (h cfnCognitoUserPoolGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoGroupKeys...)
	if err != nil {
		return err
	}
	return cfnCognitoAbsent(cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "DeleteGroup", &api.DeleteGroupInput{UserPoolId: new(api.UserPoolIdType(ids[0])), GroupName: new(api.GroupNameType(ids[1]))}))
}

func (h cfnCognitoUserPoolGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoGroupKeys...)
	if err != nil {
		return nil, err
	}
	out, err := cfnMessagingCall[api.GetGroupOutput](ctx, h.commands, "cognitoidp", "GetGroup", &api.GetGroupInput{UserPoolId: new(api.UserPoolIdType(ids[0])), GroupName: new(api.GroupNameType(ids[1]))})
	if err != nil {
		return nil, err
	}
	return cfnCognitoProject(out.Group, "UserPoolId", "GroupName", "Description", "Precedence", "RoleArn")
}

func (h cfnCognitoUserPoolGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	pool, err := cfnCognitoParent(r, "UserPoolId")
	if err != nil {
		return nil, err
	}
	groups, err := cfnCognitoGroups(ctx, h.commands, "ListGroups", map[string]any{"UserPoolId": pool})
	if err != nil {
		return nil, err
	}
	out := make([]cloudformation.ResourceDescription, 0, len(groups))
	for _, group := range groups {
		p, err := cfnCognitoProject(group, "UserPoolId", "GroupName", "Description", "Precedence", "RoleArn")
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: pool + "|" + cfnComputeValue(group.GroupName), Properties: p})
	}
	return out, nil
}

// cfnCognitoGroups pages ListGroups or AdminListGroupsForUser.
func cfnCognitoGroups(ctx context.Context, commands StepFunctionsCommands, operation string, request map[string]any) (api.GroupListType, error) {
	var groups api.GroupListType
	token := ""
	for {
		page := cfnCognitoWithout(request)
		page["Limit"] = 60
		if token != "" {
			page["NextToken"] = token
		}
		var listed *api.ListGroupsOutput
		if operation == "ListGroups" {
			in, err := cfnCognitoInput[api.ListGroupsInput](page)
			if err != nil {
				return nil, err
			}
			if listed, err = cfnMessagingCall[api.ListGroupsOutput](ctx, commands, "cognitoidp", operation, in); err != nil {
				return nil, err
			}
		} else {
			in, err := cfnCognitoInput[api.AdminListGroupsForUserInput](page)
			if err != nil {
				return nil, err
			}
			forUser, err := cfnMessagingCall[api.AdminListGroupsForUserOutput](ctx, commands, "cognitoidp", operation, in)
			if err != nil {
				return nil, err
			}
			listed = &api.ListGroupsOutput{Groups: forUser.Groups, NextToken: forUser.NextToken}
		}
		groups = append(groups, listed.Groups...)
		if token = cfnComputeValue(listed.NextToken); token == "" {
			return groups, nil
		}
	}
}

type cfnCognitoUserPoolUserToGroupAttachment struct{ commands StepFunctionsCommands }

var cfnCognitoAttachmentKeys = []string{"UserPoolId", "GroupName", "Username"}

func (h cfnCognitoUserPoolUserToGroupAttachment) Validate(p cloudformation.Properties) error {
	if err := cfnComputeRequired(p, cfnCognitoAttachmentKeys...); err != nil {
		return err
	}
	_, err := cfnCognitoInput[api.AdminAddUserToGroupInput](p)
	return err
}

func (h cfnCognitoUserPoolUserToGroupAttachment) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, cfnCognitoAttachmentKeys...), h.Validate(b)
}

func cfnCognitoAttachmentResult(ids []string) cloudformation.ResourceResult {
	id := ids[0] + "|" + ids[1] + "|" + ids[2]
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{}}
}

func (h cfnCognitoUserPoolUserToGroupAttachment) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, err := cfnCognitoInput[api.AdminAddUserToGroupInput](r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnMessagingExec(cfnCognitoClaimContext(ctx, r), h.commands, "cognitoidp", "AdminAddUserToGroup", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoAttachmentResult([]string{cfnComputeValue(in.UserPoolId), cfnComputeValue(in.GroupName), cfnComputeValue(in.Username)}), nil
}

func (h cfnCognitoUserPoolUserToGroupAttachment) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if replace, err := h.Replacement(r.Previous, r.Properties); err != nil || replace {
		if err == nil {
			err = fmt.Errorf("user to group attachment update requires replacement")
		}
		return cloudformation.ResourceResult{}, err
	}
	ids, err := cfnCognitoIdentifier(r, cfnCognitoAttachmentKeys...)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoAttachmentResult(ids), nil
}

func (h cfnCognitoUserPoolUserToGroupAttachment) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoAttachmentKeys...)
	if err != nil {
		return err
	}
	return cfnCognitoAbsent(cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "AdminRemoveUserFromGroup", &api.AdminRemoveUserFromGroupInput{UserPoolId: new(api.UserPoolIdType(ids[0])), GroupName: new(api.GroupNameType(ids[1])), Username: new(api.UsernameType(ids[2]))}))
}

func (h cfnCognitoUserPoolUserToGroupAttachment) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoAttachmentKeys...)
	if err != nil {
		return nil, err
	}
	groups, err := cfnCognitoGroups(ctx, h.commands, "AdminListGroupsForUser", map[string]any{"UserPoolId": ids[0], "Username": ids[2]})
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		if cfnComputeValue(group.GroupName) == ids[1] {
			return cloudformation.Properties{"UserPoolId": ids[0], "GroupName": ids[1], "Username": ids[2]}, nil
		}
	}
	return nil, cfnCognitoNotFound("user " + ids[2] + " in group " + ids[1])
}

func (h cfnCognitoUserPoolUserToGroupAttachment) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	pool, err := cfnCognitoParent(r, "UserPoolId")
	if err != nil {
		return nil, err
	}
	group, err := cfnCognitoParent(r, "GroupName")
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	token := ""
	for {
		page := map[string]any{"UserPoolId": pool, "GroupName": group, "Limit": 60}
		if token != "" {
			page["NextToken"] = token
		}
		in, err := cfnCognitoInput[api.ListUsersInGroupInput](page)
		if err != nil {
			return nil, err
		}
		listed, err := cfnMessagingCall[api.ListUsersInGroupOutput](ctx, h.commands, "cognitoidp", "ListUsersInGroup", in)
		if err != nil {
			return nil, err
		}
		for _, user := range listed.Users {
			name := cfnComputeValue(user.Username)
			out = append(out, cloudformation.ResourceDescription{Identifier: pool + "|" + group + "|" + name, Properties: cloudformation.Properties{"UserPoolId": pool, "GroupName": group, "Username": name}})
		}
		if token = cfnComputeValue(listed.NextToken); token == "" {
			return out, nil
		}
	}
}

type cfnCognitoUserPoolIdentityProvider struct{ commands StepFunctionsCommands }

var cfnCognitoProviderKeys = []string{"UserPoolId", "ProviderName"}

func (h cfnCognitoUserPoolIdentityProvider) Validate(p cloudformation.Properties) error {
	if err := cfnComputeRequired(p, "UserPoolId", "ProviderName", "ProviderType", "ProviderDetails"); err != nil {
		return err
	}
	_, err := cfnCognitoInput[api.CreateIdentityProviderInput](p)
	return err
}

func (h cfnCognitoUserPoolIdentityProvider) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "UserPoolId", "ProviderName", "ProviderType"), h.Validate(b)
}

func cfnCognitoProviderResult(pool, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: pool + "|" + name, Ref: name, Attributes: map[string]any{}}
}

func (h cfnCognitoUserPoolIdentityProvider) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	in, err := cfnCognitoInput[api.CreateIdentityProviderInput](r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnMessagingExec(cfnCognitoClaimContext(ctx, r), h.commands, "cognitoidp", "CreateIdentityProvider", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoProviderResult(cfnComputeValue(in.UserPoolId), cfnComputeValue(in.ProviderName)), nil
}

// Omitted mappings and identifiers are cleared, as the template declares.
func (h cfnCognitoUserPoolIdentityProvider) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoProviderKeys...)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	m := cfnCognitoWithout(r.Properties, "ProviderType")
	m["UserPoolId"], m["ProviderName"] = ids[0], ids[1]
	if _, ok := m["AttributeMapping"]; !ok {
		m["AttributeMapping"] = map[string]any{}
	}
	if _, ok := m["IdpIdentifiers"]; !ok {
		m["IdpIdentifiers"] = []any{}
	}
	in, err := cfnCognitoInput[api.UpdateIdentityProviderInput](m)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if err := cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "UpdateIdentityProvider", in); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnCognitoProviderResult(ids[0], ids[1]), nil
}

func (h cfnCognitoUserPoolIdentityProvider) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoProviderKeys...)
	if err != nil {
		return err
	}
	return cfnCognitoAbsent(cfnMessagingExec(cfnCognitoContext(ctx, r), h.commands, "cognitoidp", "DeleteIdentityProvider", &api.DeleteIdentityProviderInput{UserPoolId: new(api.UserPoolIdType(ids[0])), ProviderName: new(api.ProviderNameType(ids[1]))}))
}

func (h cfnCognitoUserPoolIdentityProvider) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	ids, err := cfnCognitoIdentifier(r, cfnCognitoProviderKeys...)
	if err != nil {
		return nil, err
	}
	out, err := cfnMessagingCall[api.DescribeIdentityProviderOutput](ctx, h.commands, "cognitoidp", "DescribeIdentityProvider", &api.DescribeIdentityProviderInput{UserPoolId: new(api.UserPoolIdType(ids[0])), ProviderName: new(api.ProviderNameType(ids[1]))})
	if err != nil {
		return nil, err
	}
	return cfnCognitoProject(out.IdentityProvider, "UserPoolId", "ProviderName", "ProviderType", "ProviderDetails", "AttributeMapping", "IdpIdentifiers")
}

func (h cfnCognitoUserPoolIdentityProvider) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	pool, err := cfnCognitoParent(r, "UserPoolId")
	if err != nil {
		return nil, err
	}
	var out []cloudformation.ResourceDescription
	token := ""
	for {
		page := map[string]any{"UserPoolId": pool, "MaxResults": 60}
		if token != "" {
			page["NextToken"] = token
		}
		in, err := cfnCognitoInput[api.ListIdentityProvidersInput](page)
		if err != nil {
			return nil, err
		}
		listed, err := cfnMessagingCall[api.ListIdentityProvidersOutput](ctx, h.commands, "cognitoidp", "ListIdentityProviders", in)
		if err != nil {
			return nil, err
		}
		for _, provider := range listed.Providers {
			id := pool + "|" + cfnComputeValue(provider.ProviderName)
			p, err := h.Read(ctx, cloudformation.ResourceRequest{PhysicalID: id, Scope: r.Scope, CloudControl: true})
			if cfnCognitoMissing(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: p})
		}
		if token = cfnComputeValue(listed.NextToken); token == "" {
			return out, nil
		}
	}
}
