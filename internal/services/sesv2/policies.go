package sesv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	classic "stackd/internal/awsapi/ses"
	api "stackd/internal/awsapi/sesv2"
	"strings"
)

func (s *Service) registerIdentityPolicies() {
	register(s, "CreateEmailIdentityPolicy", s.createIdentityPolicy)
	register(s, "UpdateEmailIdentityPolicy", s.updateIdentityPolicy)
	register(s, "GetEmailIdentityPolicies", s.getIdentityPolicies)
	register(s, "DeleteEmailIdentityPolicy", s.deleteIdentityPolicy)
}

func identityKey(scope Scope, name string) (ResourceKey, error) {
	if !strings.HasPrefix(name, "arn:") {
		return ResourceKey{scope, name}, nil
	}
	parts := strings.SplitN(name, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "ses" || parts[3] != scope.Region || len(parts[4]) != 12 || !strings.HasPrefix(parts[5], "identity/") || len(parts[5]) == len("identity/") {
		return ResourceKey{}, bad("Invalid identity ARN.")
	}
	for _, ch := range parts[4] {
		if ch < '0' || ch > '9' {
			return ResourceKey{}, bad("Invalid identity ARN.")
		}
	}
	scope.AccountID = parts[4]
	return ResourceKey{scope, strings.TrimPrefix(parts[5], "identity/")}, nil
}

func (s *Service) policyIdentity(tx Transaction, action, name string) (Identity, error) {
	scope := scopeFor(tx.Context())
	key, e := identityKey(scope, name)
	if e != nil {
		return Identity{}, e
	}
	if key.Scope != scope {
		return Identity{}, failure("AccessDeniedException", "Identity policies can only be managed by the identity owner.", 403)
	}
	id, e := tx.Identity(key)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return Identity{}, e
	}
	if authErr := s.authorize(tx, action, key.ARN("identity"), id.Tags, nil); authErr != nil {
		return Identity{}, authErr
	}
	return id, e
}

func (s *Service) putIdentityPolicy(tx Transaction, action, name, policyName, document string) error {
	id, e := s.policyIdentity(tx, action, name)
	if e != nil {
		return e
	}
	if !resourceName.MatchString(policyName) {
		return bad("Invalid policy name.")
	}
	_, exists := id.Policies[policyName]
	if action == "CreateEmailIdentityPolicy" && exists {
		return failure("AlreadyExistsException", "Policy <"+policyName+"> already exists", 400)
	}
	if action == "UpdateEmailIdentityPolicy" && !exists {
		return failure("NotFoundException", "Policy <"+policyName+"> does not exist", 404)
	}
	if document == "" || len(document) > 4096 {
		return bad("The policy must contain between 1 and 4096 bytes.")
	}
	document, e = validateIdentityPolicy(document, id.Key)
	if e != nil {
		return identityPolicyError(tx, e)
	}
	binder, ok := s.authorizer.(authorization.PolicyBinder)
	if !ok {
		return unsupported("Identity policy principal binding is not configured.")
	}
	bound, e := binder.BindResourcePolicy(tx.Context(), document, authorization.ResourcePolicyOptions{})
	if e != nil {
		return identityPolicyError(tx, e)
	}
	if _, exists := id.Policies[policyName]; !exists && len(id.Policies) >= 20 {
		return failure("LimitExceededException", "An identity can have at most 20 sending authorization policies.", 400)
	}
	if id.Policies == nil {
		id.Policies = map[string]authorization.BoundPolicy{}
	}
	id.Policies[policyName] = bound
	return tx.PutIdentity(id)
}

func (s *Service) removeIdentityPolicy(tx Transaction, action, name, policyName string) error {
	id, e := s.policyIdentity(tx, action, name)
	if isClassic(tx.Context()) && errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	delete(id.Policies, policyName)
	return tx.PutIdentity(id)
}

func (s *Service) renderedIdentityPolicies(tx Reader, id Identity) (api.PolicyMap, error) {
	out := make(api.PolicyMap, len(id.Policies))
	if len(id.Policies) == 0 {
		return out, nil
	}
	binder, ok := s.authorizer.(authorization.PolicyBinder)
	if !ok {
		return nil, unsupported("Identity policy principal binding is not configured.")
	}
	for name, bound := range id.Policies {
		document, e := binder.RenderResourcePolicy(tx.Context(), bound)
		if e != nil {
			return nil, e
		}
		out[api.PolicyName(name)] = api.Policy(document)
	}
	return out, nil
}

func (s *Service) createIdentityPolicy(tx Transaction, in *api.CreateEmailIdentityPolicyInput) (*api.CreateEmailIdentityPolicyOutput, error) {
	return &api.CreateEmailIdentityPolicyOutput{}, s.putIdentityPolicy(tx, "CreateEmailIdentityPolicy", value(in.EmailIdentity), value(in.PolicyName), value(in.Policy))
}
func (s *Service) updateIdentityPolicy(tx Transaction, in *api.UpdateEmailIdentityPolicyInput) (*api.UpdateEmailIdentityPolicyOutput, error) {
	return &api.UpdateEmailIdentityPolicyOutput{}, s.putIdentityPolicy(tx, "UpdateEmailIdentityPolicy", value(in.EmailIdentity), value(in.PolicyName), value(in.Policy))
}
func (s *Service) deleteIdentityPolicy(tx Transaction, in *api.DeleteEmailIdentityPolicyInput) (*api.DeleteEmailIdentityPolicyOutput, error) {
	return &api.DeleteEmailIdentityPolicyOutput{}, s.removeIdentityPolicy(tx, "DeleteEmailIdentityPolicy", value(in.EmailIdentity), value(in.PolicyName))
}
func (s *Service) getIdentityPolicies(tx Transaction, in *api.GetEmailIdentityPoliciesInput) (*api.GetEmailIdentityPoliciesOutput, error) {
	id, e := s.policyIdentity(tx, "GetEmailIdentityPolicies", value(in.EmailIdentity))
	if e != nil {
		return nil, e
	}
	policies, e := s.renderedIdentityPolicies(tx, id)
	return &api.GetEmailIdentityPoliciesOutput{Policies: policies}, e
}

func (c *ClassicService) putIdentityPolicy(tx Transaction, in *classic.PutIdentityPolicyInput) (*classic.PutIdentityPolicyOutput, error) {
	return &classic.PutIdentityPolicyOutput{}, c.owner.putIdentityPolicy(tx, "PutIdentityPolicy", value(in.Identity), value(in.PolicyName), value(in.Policy))
}
func (c *ClassicService) deleteIdentityPolicy(tx Transaction, in *classic.DeleteIdentityPolicyInput) (*classic.DeleteIdentityPolicyOutput, error) {
	return &classic.DeleteIdentityPolicyOutput{}, c.owner.removeIdentityPolicy(tx, "DeleteIdentityPolicy", value(in.Identity), value(in.PolicyName))
}
func (c *ClassicService) getIdentityPolicies(tx Transaction, in *classic.GetIdentityPoliciesInput) (*classic.GetIdentityPoliciesOutput, error) {
	id, e := c.owner.policyIdentity(tx, "GetIdentityPolicies", value(in.Identity))
	if e != nil && !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	policies, e := c.owner.renderedIdentityPolicies(tx, id)
	if e != nil {
		return nil, e
	}
	out := &classic.GetIdentityPoliciesOutput{Policies: classic.PolicyMap{}}
	for _, name := range in.PolicyNames {
		if document, ok := policies[api.PolicyName(name)]; ok {
			out.Policies[name] = classic.Policy(document)
		}
	}
	return out, nil
}
func (c *ClassicService) listIdentityPolicies(tx Transaction, in *classic.ListIdentityPoliciesInput) (*classic.ListIdentityPoliciesOutput, error) {
	id, e := c.owner.policyIdentity(tx, "ListIdentityPolicies", value(in.Identity))
	if e != nil && !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	out := &classic.ListIdentityPoliciesOutput{PolicyNames: classic.PolicyNameList{}}
	for _, name := range slices.Sorted(maps.Keys(id.Policies)) {
		out.PolicyNames = append(out.PolicyNames, classic.PolicyName(name))
	}
	return out, nil
}

// resolveSendingIdentity resolves an explicit owner ARN without changing caller
// authority. Missing identities retain their key so the ordinary send rejection
// and IAM resource checks still run against the requested identity.
func (s *Service) resolveSendingIdentity(tx Transaction, address, arn string) (Identity, string, error) {
	key := ResourceKey{scopeFor(tx.Context()), address}
	if arn != "" {
		var e error
		key, e = identityKey(key.Scope, arn)
		if e != nil {
			return Identity{}, "", e
		}
		if !strings.HasPrefix(arn, "arn:") || key.Name != address {
			return Identity{}, "", bad("The sending authorization identity does not match the email address.")
		}
	}
	id, e := tx.Identity(key)
	if errors.Is(e, ErrNotFound) {
		return Identity{Key: key}, key.ARN("identity"), nil
	}
	return id, key.ARN("identity"), e
}

func (s *Service) authorizeSendingIdentity(tx Transaction, action, arn string, identity Identity, conditions map[string][]string) error {
	request := s.authorizationRequest(tx, action, arn, identity.Tags, conditions)
	request.ResourcePolicies = make([]authorization.BoundPolicy, 0, len(identity.Policies))
	for _, name := range slices.Sorted(maps.Keys(identity.Policies)) {
		request.ResourcePolicies = append(request.ResourcePolicies, identity.Policies[name])
	}
	if rejected := s.authorizer.Authorize(tx.Context(), request); rejected != nil {
		return rejected
	}
	return nil
}

func identityPolicyError(tx Reader, e error) error {
	if isClassic(tx.Context()) {
		return failure("InvalidPolicy", e.Error(), 400)
	}
	return bad(e.Error())
}

// IAM owns the policy language. SES additionally requires every statement to
// name its attached identity and presents numeric AWS principals as root ARNs.
func validateIdentityPolicy(document string, key ResourceKey) (string, error) {
	compiled, e := policy.ParseResource([]byte(document))
	if e != nil {
		return "", e
	}
	var raw struct{ Statement json.RawMessage }
	if e = json.Unmarshal([]byte(document), &raw); e != nil {
		return "", e
	}
	statements := []json.RawMessage{raw.Statement}
	if bytes.HasPrefix(bytes.TrimSpace(raw.Statement), []byte("[")) {
		if e = json.Unmarshal(raw.Statement, &statements); e != nil {
			return "", e
		}
	}
	for _, statement := range statements {
		var fields struct{ Resource json.RawMessage }
		if e = json.Unmarshal(statement, &fields); e != nil {
			return "", e
		}
		var resource string
		resources := []string{}
		if e = json.Unmarshal(fields.Resource, &resource); e == nil {
			resources = append(resources, resource)
		} else if e = json.Unmarshal(fields.Resource, &resources); e != nil {
			return "", errors.New("each sending policy statement must name its identity resource")
		}
		for _, resource := range resources {
			if resource != key.ARN("identity") {
				return "", errors.New("Expected the resource to be '" + key.ARN("identity") + "' but was '" + resource + "'.")
			}
		}
	}
	replacements := map[string]string{}
	for _, principal := range compiled.AWSPrincipals() {
		if len(principal) != 12 {
			continue
		}
		numeric := true
		for _, ch := range principal {
			if ch < '0' || ch > '9' {
				numeric = false
				break
			}
		}
		if numeric {
			replacements[principal] = "arn:" + key.Partition + ":iam::" + principal + ":root"
		}
	}
	if len(replacements) != 0 {
		canonical, e := policy.RewriteResourcePrincipals([]byte(document), replacements)
		return string(canonical), e
	}
	var compact bytes.Buffer
	if e = json.Compact(&compact, []byte(document)); e != nil {
		return "", e
	}
	return compact.String(), nil
}
