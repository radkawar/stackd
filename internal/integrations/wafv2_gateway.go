package integrations

import (
	"context"
	"errors"

	"stackd/internal/services/apigateway"
	"stackd/internal/services/apigatewayexec"
	"stackd/internal/services/wafv2"
)

// WAFRESTStages resolves REST API stage incarnations for AWS WAF associations
// from the API Gateway owner without borrowing caller API Gateway permissions.
type WAFRESTStages struct{ Gateway *apigateway.Service }

func (s WAFRESTStages) RESTStageIncarnation(ctx context.Context, scope wafv2.Scope, apiID, stage string) (string, error) {
	at, err := s.Gateway.StageIncarnation(ctx, apigateway.Scope{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, apiID, stage)
	if errors.Is(err, apigateway.ErrNotFound) {
		return at, wafv2.ErrNotFound
	}
	return at, err
}

// GatewayWebACLs applies the AWS WAF owner's web ACL to REST stage requests.
type GatewayWebACLs struct{ WAF *wafv2.Service }

func (g GatewayWebACLs) InspectStage(ctx context.Context, r apigatewayexec.WebACLRequest) (apigatewayexec.WebACLVerdict, error) {
	v, err := g.WAF.InspectRESTStage(ctx, wafv2.Scope{Partition: r.Partition, AccountID: r.AccountID, Region: r.Region}, r.APIID, r.Stage, &wafv2.HTTPRequest{
		Method: r.Method, URI: r.URI, RawQuery: r.RawQuery, HTTPVersion: r.Proto, SourceIP: r.SourceIP, Header: r.Header, Body: r.Body,
	})
	if err != nil {
		return apigatewayexec.WebACLVerdict{}, err
	}
	return apigatewayexec.WebACLVerdict{Blocked: v.Blocked, Custom: v.Custom, Status: v.Status, Headers: v.Headers, Body: v.Body, ContentType: v.ContentType, InsertHeaders: v.InsertHeaders}, nil
}
