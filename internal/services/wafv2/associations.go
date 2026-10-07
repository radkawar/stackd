package wafv2

import (
	"context"
	"errors"
	"regexp"
	"strings"

	api "stackd/internal/awsapi/wafv2"
	"stackd/internal/awswire"
)

func registerAssociations(s *Service) {
	register(s, "AssociateWebACL", s.associate)
	register(s, "DisassociateWebACL", s.disassociate)
	register(s, "GetWebACLForResource", s.webACLForResource)
	register(s, "ListResourcesForWebACL", s.listResources)
}

type associationOwnerKey struct{}

// WithAssociationOwner constrains trusted in-process association commands to
// one owner. HTTP inputs cannot set this constraint; incomplete owners fail
// closed. It does not authorize the caller.
func WithAssociationOwner(ctx context.Context, owner AssociationOwner) context.Context {
	return context.WithValue(ctx, associationOwnerKey{}, owner)
}

func associationOwnerFor(ctx context.Context) (AssociationOwner, bool, *awswire.Error) {
	owner, present := ctx.Value(associationOwnerKey{}).(AssociationOwner)
	if present && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return AssociationOwner{}, false, failure("WAFInvalidOperationException", "The association owner identity is incomplete.", 400)
	}
	return owner, present, nil
}

var stageName = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,128}$`)

// RESTStageARN is the API Gateway stage ARN that AWS WAF associates.
func RESTStageARN(sc Scope, apiID, stage string) string {
	return "arn:" + sc.Partition + ":apigateway:" + sc.Region + "::/restapis/" + apiID + "/stages/" + stage
}

type protected struct{ apiID, stage string }

// protectedResource parses an associable resource ARN. API Gateway REST API
// stages are the only protected resource with an implemented request path.
func protectedResource(sc Scope, arn string) (protected, error) {
	prefix := "arn:" + sc.Partition + ":apigateway:" + sc.Region + "::/restapis/"
	if rest, ok := strings.CutPrefix(arn, prefix); ok {
		apiID, stage, ok := strings.Cut(rest, "/stages/")
		if ok && apiID != "" && !strings.Contains(apiID, "/") && stageName.MatchString(stage) {
			return protected{apiID, stage}, nil
		}
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" {
		switch parts[2] {
		case "elasticloadbalancing", "appsync", "cognito-idp", "apprunner", "ec2", "amplify", "bedrock-agentcore":
			return protected{}, invalidParameter("RESOURCE_ARN", arn, "AWS WAF association with "+parts[2]+" resources is not implemented; only API Gateway REST API stages are supported")
		}
	}
	return protected{}, invalidParameter("RESOURCE_ARN", arn, "The resource ARN must identify an API Gateway REST API stage in this account and Region")
}

// incarnation resolves the protected resource's current incarnation through
// its owner, joining the caller's transaction.
func (s *Service) incarnation(ctx context.Context, sc Scope, p protected) (string, error) {
	if s.resources == nil {
		return "", failure("WAFUnavailableEntityException", "API Gateway stage resolution is not configured", 400)
	}
	at, err := s.resources.RESTStageIncarnation(ctx, sc, p.apiID, p.stage)
	if errors.Is(err, ErrNotFound) {
		return "", nonexistent("AWS WAF couldn’t find the API Gateway stage " + p.apiID + "/" + p.stage)
	}
	return at, err
}

// live reports whether an association still protects its resource incarnation.
func (s *Service) live(ctx context.Context, a Association) (bool, error) {
	p, err := protectedResource(a.Scope, a.ResourceARN)
	if err != nil {
		return false, nil
	}
	at, err := s.incarnation(ctx, a.Scope, p)
	var wire *awswire.Error
	if errors.As(err, &wire) && wire.Code == "WAFNonexistentItemException" {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return at == a.ResourceIncarnation, nil
}

func (s *Service) liveAssociations(ctx context.Context, r Reader, webACL string) ([]Association, error) {
	rows, err := r.Associations(scopeFor(ctx), webACL)
	if err != nil {
		return nil, err
	}
	out := rows[:0]
	for _, a := range rows {
		ok, err := s.live(ctx, a)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

func (s *Service) authorizeResource(ctx context.Context, action, resource string) error {
	if err := s.authorize(ctx, "wafv2:"+action, resource, nil, nil); err != nil {
		return err
	}
	return s.authorize(ctx, "apigateway:SetWebACL", resource, nil, nil)
}

func (s *Service) associate(ctx context.Context, t Transaction, in *api.AssociateWebACLInput) (*api.AssociateWebACLOutput, error) {
	owner, owned, werr := associationOwnerFor(ctx)
	if werr != nil {
		return nil, werr
	}
	sc := scopeFor(ctx)
	resource := value(in.ResourceArn)
	p, err := protectedResource(sc, resource)
	if err != nil {
		return nil, err
	}
	acl, err := s.webACLByARN(ctx, t, value(in.WebACLArn), "AssociateWebACL")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(ctx, "AssociateWebACL", resource); err != nil {
		return nil, err
	}
	at, err := s.incarnation(ctx, sc, p)
	if err != nil {
		return nil, err
	}
	existing, err := t.Association(sc, resource)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return nil, err
	case existing.ResourceIncarnation == at && owned && existing.Owner != owner && !sameLogicalOwner(existing.Owner, owner):
		return nil, failure("WAFInvalidOperationException", "The resource is already associated with a web ACL by a different owner.", 400)
	case existing.ResourceIncarnation == at && existing.WebACLARN == acl.ARN && existing.Owner == owner:
		return &api.AssociateWebACLOutput{}, nil
	}
	a := Association{Scope: sc, ResourceARN: resource, WebACLARN: acl.ARN, ResourceIncarnation: at, Owner: owner, Created: s.clock.Now().UTC()}
	return &api.AssociateWebACLOutput{}, t.PutAssociation(a)
}

func (s *Service) disassociate(ctx context.Context, t Transaction, in *api.DisassociateWebACLInput) (*api.DisassociateWebACLOutput, error) {
	owner, owned, werr := associationOwnerFor(ctx)
	if werr != nil {
		return nil, werr
	}
	sc := scopeFor(ctx)
	resource := value(in.ResourceArn)
	if _, err := protectedResource(sc, resource); err != nil {
		return nil, err
	}
	if err := s.authorizeResource(ctx, "DisassociateWebACL", resource); err != nil {
		return nil, err
	}
	existing, err := t.Association(sc, resource)
	if errors.Is(err, ErrNotFound) {
		return &api.DisassociateWebACLOutput{}, nil
	}
	if err != nil {
		return nil, err
	}
	if owned && existing.Owner != owner {
		return nil, failure("WAFInvalidOperationException", "The resource's web ACL association belongs to a different owner.", 400)
	}
	return &api.DisassociateWebACLOutput{}, t.DeleteAssociation(sc, resource)
}

func (s *Service) webACLForResource(ctx context.Context, t Transaction, in *api.GetWebACLForResourceInput) (*api.GetWebACLForResourceOutput, error) {
	sc := scopeFor(ctx)
	resource := value(in.ResourceArn)
	p, err := protectedResource(sc, resource)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "wafv2:GetWebACLForResource", resource, nil, nil); err != nil {
		return nil, err
	}
	at, err := s.incarnation(ctx, sc, p)
	if err != nil {
		return nil, err
	}
	a, err := t.Association(sc, resource)
	if errors.Is(err, ErrNotFound) || err == nil && a.ResourceIncarnation != at {
		return &api.GetWebACLForResourceOutput{}, nil
	}
	if err != nil {
		return nil, err
	}
	acl, err := t.WebACL(sc, a.WebACLARN)
	if err != nil {
		return nil, err
	}
	return &api.GetWebACLForResourceOutput{WebACL: acl.model()}, nil
}

// sameLogicalOwner admits a replacement incarnation of the same stack resource,
// which CloudFormation creates before deleting its predecessor.
func sameLogicalOwner(a, b AssociationOwner) bool {
	return a.StackID == b.StackID && a.LogicalID == b.LogicalID
}

func (s *Service) listResources(ctx context.Context, t Transaction, in *api.ListResourcesForWebACLInput) (*api.ListResourcesForWebACLOutput, error) {
	acl, err := s.webACLByARN(ctx, t, value(in.WebACLArn), "ListResourcesForWebACL")
	if err != nil {
		return nil, err
	}
	out := &api.ListResourcesForWebACLOutput{ResourceArns: api.ResourceArns{}}
	// AWS WAF lists APPLICATION_LOAD_BALANCER resources when ResourceType is omitted.
	if value(in.ResourceType) != "API_GATEWAY" {
		return out, nil
	}
	rows, err := s.liveAssociations(ctx, t, acl.ARN)
	if err != nil {
		return nil, err
	}
	for _, a := range rows {
		out.ResourceArns = append(out.ResourceArns, api.ResourceArn(a.ResourceARN))
	}
	return out, nil
}
