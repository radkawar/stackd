package integrations

import (
	"context"
	"net/http"
	"strings"

	"stackd/compute/network"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// SetHandler connects endpoint tunnels to stackd's actual HTTP authentication,
// protocol decoder and service owners. No endpoint proxy implements AWS responses.
func (a *LambdaFunctionNetworks) SetHandler(handler http.Handler) {
	a.handlerMu.Lock()
	defer a.handlerMu.Unlock()
	a.handler = handler
}

func (a *LambdaFunctionNetworks) hasHandler() bool {
	a.handlerMu.RLock()
	defer a.handlerMu.RUnlock()
	return a.handler != nil
}

func (a *LambdaFunctionNetworks) endpointHandler(endpoint network.ServiceEndpoint) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.handlerMu.RLock()
		handler := a.handler
		a.handlerMu.RUnlock()
		if handler == nil {
			http.Error(w, "The authenticated AWS endpoint handler is unavailable", http.StatusServiceUnavailable)
			return
		}
		guard := &lambdaEndpointGuard{adapter: a, endpoint: endpoint}
		handler.ServeHTTP(w, r.WithContext(authorization.WithNetworkEndpointGuard(r.Context(), guard)))
	})
}

func (l *lambdaFunctionNetworkLease) BindExecutionCredential(accessKey string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.adapter.lifecycleMu.Lock()
	defer l.adapter.lifecycleMu.Unlock()
	if l.closed || accessKey == "" {
		return
	}
	if l.adapter.credentials == nil {
		l.adapter.credentials = make(map[string]*lambdaFunctionNetworkLease)
	}
	l.accessKey = accessKey
	l.adapter.credentials[accessKey] = l
}

func (l *lambdaFunctionNetworkLease) EndpointVariables() map[string]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.services == nil {
		return nil
	}
	return l.services.EndpointVariables()
}

type lambdaEndpointGuard struct {
	adapter  *LambdaFunctionNetworks
	endpoint network.ServiceEndpoint
	document *policy.Document
	context  map[string][]string
}

func endpointDenied(message string) *awswire.Error {
	return &awswire.Error{Code: "AccessDenied", Message: message, StatusCode: http.StatusForbidden}
}

func (g *lambdaEndpointGuard) Context(ctx context.Context, request authorization.Request) (map[string][]string, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	g.adapter.lifecycleMu.Lock()
	lease := g.adapter.credentials[m.AccessKeyID]
	g.adapter.lifecycleMu.Unlock()
	if lease == nil {
		return nil, endpointDenied("The endpoint request is not bound to a live Lambda execution environment.")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed || lease.nativeClosed || m.IssuerARN != lease.session.roleARN || m.Partition != lease.session.function.Partition || m.AccountID != lease.session.function.Account || m.Region != lease.session.function.Region {
		return nil, endpointDenied("The endpoint request belongs to another execution role or AWS scope.")
	}
	claims := m.SessionContext["lambda:sourcefunctionarn"]
	if len(claims) != 1 || claims[0] != lease.function {
		return nil, endpointDenied("The endpoint request has no authenticated Lambda source-function identity.")
	}
	service, _, ok := strings.Cut(request.Action, ":")
	if !ok || g.endpoint.Service != "" && !strings.EqualFold(service, g.endpoint.Service) {
		return nil, endpointDenied("The request service does not belong to this VPC endpoint.")
	}
	if lease.spec.NetworkID != g.endpoint.Network.NetworkID {
		return nil, endpointDenied("The endpoint belongs to another VPC network.")
	}
	// The registered native credential and authenticated STS source claim prove
	// Lambda's service origin. Public headers cannot install these attributes.
	m.InvokedBy = "lambda.amazonaws.com"
	owner := awsctx.WithMetadata(authorization.WithoutNetworkEndpointGuard(ctx), m)
	access, err := g.adapter.EC2.ResolveLambdaFunctionEndpoint(owner, lease.function, lease.incarnation, lease.interfaceID, g.endpoint.ID, g.endpoint.Kind, strings.ToLower(service))
	if err != nil {
		return nil, endpointDenied("The current EC2 endpoint route does not authorize this function: " + err.Error())
	}
	document, err := policy.ParseResource([]byte(access.PolicyDocument))
	if err != nil {
		return nil, endpointDenied("The current VPC endpoint policy cannot be evaluated: " + err.Error())
	}
	g.document = document
	g.context = map[string][]string{"aws:sourcevpce": {access.ID}, "aws:sourcevpc": {access.VPCID}, "aws:vpcsourceip": {access.SourceIP}}
	return g.context, nil
}

func (g *lambdaEndpointGuard) Authorize(ctx context.Context, request authorization.Request, principal policy.Principal) *awswire.Error {
	if g.document == nil {
		values, rejected := g.Context(ctx, request)
		if rejected != nil {
			return rejected
		}
		if request.Context == nil {
			request.Context = make(map[string][]string)
		}
		for key, values := range values {
			request.Context[key] = values
		}
	}
	decision, err := policy.EvaluateResource(g.document, policy.Request{Action: request.Action, ActionAliases: request.PolicyActionAliases, AdditionalDenyActions: request.AdditionalDenyActions, Resource: request.ResourceARN, Context: request.Context, ContextTypes: request.ContextTypes}, principal)
	if err != nil {
		return endpointDenied("The VPC endpoint policy cannot authorize this request: " + err.Error())
	}
	if decision.Decision != policy.Allow {
		return endpointDenied("The VPC endpoint policy does not allow this service action and resource.")
	}
	return nil
}

var _ authorization.NetworkEndpointGuard = (*lambdaEndpointGuard)(nil)
