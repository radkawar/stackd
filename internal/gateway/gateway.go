package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"stackd/clock"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// RequestOrigin attributes authenticated runtime requests without changing identity.
type RequestOrigin interface {
	InvocationParent(accessKeyID string) string
}

// Sources may observe public outcomes, including pre-dispatch rejections.
type httpObserver interface {
	ObserveHTTP(http.ResponseWriter, *http.Request) (http.ResponseWriter, *http.Request, func(*http.Request))
}

type Config struct {
	AccountID    string
	MaxBodyBytes int64
	Credentials  CredentialResolver
	Regions      RegionAccess
	Clock        clock.Clock
	// Activity records authenticated operation attempts before authorization.
	Activity ActivityRecorder
	// Origin resolves an active invocation only after signature verification.
	Origin RequestOrigin
	// UnsignedRegion is the trusted fallback endpoint region for public Query,
	// JSON and S3 requests, which carry no verified SigV4 credential scope.
	UnsignedRegion string
}

type Gateway struct {
	services []Service
	config   Config
}

func New(registry *Registry, config Config) (*Gateway, error) {
	if config.Clock == nil {
		config.Clock = clock.Real{}
	}
	if config.AccountID == "" {
		config.AccountID = "000000000000"
	}
	if !accountPattern.MatchString(config.AccountID) {
		return nil, fmt.Errorf("account ID must have 12 digits")
	}
	if config.MaxBodyBytes == 0 {
		// Lambda direct ZIP uploads base64-encode up to 50 MiB. This also covers
		// IAM's 10 MB SAML metadata after AWS Query percent encoding.
		config.MaxBodyBytes = 70 << 20
	}
	if config.MaxBodyBytes < 1 {
		return nil, fmt.Errorf("maximum body size must be positive")
	}
	if config.UnsignedRegion == "" {
		config.UnsignedRegion = "us-east-1"
	}
	if awscatalog.RegionPartition(config.UnsignedRegion) == "" {
		return nil, fmt.Errorf("unsigned region must be an SDK-described AWS region")
	}
	if registry == nil {
		return nil, fmt.Errorf("registry is required")
	}
	if config.Credentials == nil {
		config.Credentials = identity.NewStore(config.AccountID)
	}
	return &Gateway{services: slices.Clone(registry.services), config: config}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	r = r.WithContext(awsctx.WithMetadata(r.Context(), awsctx.Metadata{RequestID: requestID}))
	if r.URL.Path == "/_stackd/health" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		awswire.WriteJSON(w, r, struct {
			Status   string       `json:"status"`
			Services []Capability `json:"services"`
		}{Status: "available", Services: g.Capabilities()})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, g.config.MaxBodyBytes)
	if g.serveDataPlane(w, r) {
		return
	}
	resourceService, resourceRegion, resourceMatched := g.resourceEndpoint(r)
	if resourceMatched && !hasSigningMaterial(r.Header, r.URL.Query()) {
		awswire.JSONError(w, r, &awswire.Error{Code: "MissingAuthenticationToken", Message: "Request must contain a valid AWS signature.", StatusCode: http.StatusForbidden})
		return
	}
	// S3 preflight is anonymous even when a browser includes signing fields.
	if !resourceMatched && r.Method == http.MethodOptions && g.serveS3CORS(w, r, nil, g.config.UnsignedRegion) {
		return
	}
	if !resourceMatched && g.serveCognitoDiscovery(w, r) {
		return
	}
	if !resourceMatched && g.serveCognitoOAuth(w, r) {
		return
	}
	if !resourceMatched && g.servePublicJSON(w, r) {
		return
	}
	if !resourceMatched && g.servePublicIdentityREST(w, r) {
		return
	}
	if !hasSigningMaterial(r.Header, r.URL.Query()) {
		if !g.serveUnsignedS3(w, r) {
			g.serveUnsignedQuery(w, r)
		}
		return
	}
	scope, err := parseCredential(r)
	var service *Service
	var routeErr *awswire.Error
	if resourceMatched {
		service, routeErr = selectProtocol(r, resourceService)
	} else {
		service, routeErr = g.route(r, scope.service)
	}
	if err != nil && service == nil {
		service = g.s3Service(r)
	}
	if service != nil {
		if observer, ok := service.Provider.(httpObserver); ok {
			metadata := awsctx.FromContext(r.Context())
			metadata.Region = g.config.UnsignedRegion
			metadata.Partition = awscatalog.RegionPartition(metadata.Region)
			r = r.WithContext(awsctx.WithMetadata(r.Context(), metadata))
			var finish func(*http.Request)
			w, r, finish = observer.ObserveHTTP(w, r)
			defer func() { finish(r) }()
		}
	}
	if g.serveS3CORS(w, r, service, scope.region) {
		return
	}
	writeError := func(apiErr *awswire.Error) {
		apiErr = serviceAuthenticationError(service, apiErr)
		if service != nil && service.Protocol == Query {
			awswire.QueryError(w, r, service.Namespace, apiErr)
		} else if service != nil && service.Protocol == EC2Query {
			awswire.EC2QueryError(w, r, apiErr)
		} else if service != nil && service.Protocol == RestJSON {
			awswire.RESTJSONError(w, r, service.Model, apiErr)
		} else if service != nil && service.Protocol == RestXML {
			awswire.RESTXMLError(w, r, service.Model, apiErr)
		} else if service != nil && service.Protocol == RPCV2CBOR {
			awswire.RPCV2Error(w, r, service.Model, apiErr)
		} else if r.Header.Get("X-Amz-Target") != "" || strings.Contains(r.Header.Get("Content-Type"), "json") {
			awswire.JSONError(w, r, apiErr)
		} else {
			awswire.QueryError(w, r, "", apiErr)
		}
	}
	if service != nil && service.Name == "s3" {
		if failure := validateS3Authentication(r); failure != nil {
			writeError(failure)
			return
		}
	}
	if resourceMatched && (scope.service != service.SigningName || scope.region != resourceRegion) {
		writeError(&awswire.Error{Code: "SignatureDoesNotMatch", Message: "Credential scope does not match the requested endpoint", StatusCode: http.StatusForbidden})
		return
	}
	if err != nil {
		writeError(&awswire.Error{Code: "IncompleteSignature", Message: err.Error(), StatusCode: 400})
		return
	}
	if routeErr != nil {
		writeError(routeErr)
		return
	}
	authenticated, wire := g.authenticate(r, scope, service.Model)
	if wire != nil {
		writeError(wire)
		return
	}
	r = authenticated
	if apiErr := g.checkRegion(r, service); apiErr != nil {
		writeError(apiErr)
		return
	}
	// Signature verification restores the consumed body. Preserve the explicit
	// configured bound so net/http.ParseForm does not substitute its unrelated
	// 10 MB default for valid, larger AWS Query payloads.
	r.Body = http.MaxBytesReader(w, r.Body, g.config.MaxBodyBytes)
	g.serveOperation(w, r, service, writeError)
}

func (g *Gateway) serveOperation(w http.ResponseWriter, r *http.Request, service *Service, writeError func(*awswire.Error)) {
	if provider, ok := service.Provider.(privateOperationProvider); ok {
		if action, matched := provider.PrivateOperation(r); matched {
			if err := g.recordKnownActivity(r.Context(), service, action); err != nil {
				writeError(&awswire.Error{Code: "ServiceFailure", Message: "Unable to record authenticated activity", StatusCode: http.StatusInternalServerError})
				return
			}
			provider.ServePrivateOperation(w, r)
			return
		}
	}
	action, input, failure := g.operationInput(r, service)
	if failure != nil {
		writeError(recordRequestError(r.Context(), service, action, &input, failure))
		return
	}
	if limiter, ok := service.Provider.(jsonRequestLimiter); ok {
		if limit := limiter.JSONRequestLimit(action); limit > 0 && len(input.JSON) > limit {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
	}
	if err := g.recordActivity(r.Context(), service, action); err != nil {
		writeError(&awswire.Error{Code: "ServiceFailure", Message: "Unable to record authenticated activity", StatusCode: http.StatusInternalServerError})
		return
	}
	m := awsctx.FromContext(r.Context())
	if service.SigningName == "iam" {
		if m.SessionType == string(identity.SessionTypeGetSessionToken) && !m.MFAPresent {
			writeError(recordRequestError(r.Context(), service, action, &input, &awswire.Error{Code: "AccessDenied", Message: "GetSessionToken credentials without MFA cannot call IAM", StatusCode: 403}))
			return
		}
		if m.SessionType == string(identity.SessionTypeFederation) {
			writeError(recordRequestError(r.Context(), service, action, &input, &awswire.Error{Code: "AccessDenied", Message: "Federated user credentials cannot call IAM", StatusCode: 403}))
			return
		}
	}
	if admitter, ok := service.Provider.(requestAdmitter); ok {
		if rejected := admitter.AdmitRequest(r.Context(), action); rejected != nil {
			writeError(recordRequestError(r.Context(), service, action, nil, rejected))
			return
		}
	}
	if service.Decode != nil {
		decoded, err := service.Decode(action, input)
		if err != nil {
			writeError(recordRequestError(r.Context(), service, action, &input, decodingError(r.Context(), service, action, input, err)))
			return
		}
		r = r.WithContext(awsapi.WithDecodedRequest(r.Context(), decoded))
	}
	service.Provider.ServeHTTP(w, r)
}

func (g *Gateway) route(r *http.Request, signingName string) (*Service, *awswire.Error) {
	prefix, _, hasTarget := awswire.JSONTarget(r.Header.Get("X-Amz-Target"))
	s3Control := signingName == "s3" && g.s3ControlRequest(r)
	var selected *Service
	for i := range g.services {
		service := &g.services[i]
		// An unparseable signature may still name a JSON service for its error
		// protocol. The caller rejects that signature before any dispatch.
		if service.SigningName != signingName && (signingName != "" || !hasTarget || prefix != service.TargetPrefix) {
			continue
		}
		if signingName == "s3" && service.Protocol == RestXML && (service.Name == "s3" || service.Name == "s3control") {
			if (service.Name == "s3control") != s3Control {
				continue
			}
		}
		if signingName == "rds" && service.Name == "rds" && service.Protocol == Query {
			// RDS is the shared Query composition owner, independent of
			// registration order or which official SDK produced the request.
			selected = service
			break
		}
		// Generated REST routes take precedence below. A shared Query
		// frontend is the fallback regardless of registration order.
		if selected == nil || selected.Protocol == RestJSON && service.Protocol == Query {
			selected = service
		}
		if service.Protocol == RestJSON {
			if _, _, matched := service.Model.MatchHTTPOperation(r.Method, r.URL.EscapedPath(), r.URL.Query(), r.Header); matched {
				selected = service
				break
			}
		}
		if hasTarget && prefix == service.TargetPrefix {
			selected = service
			break
		}
	}
	if selected == nil {
		return nil, &awswire.Error{Code: "UnknownOperationException", Message: "Service is not implemented: " + signingName, StatusCode: 400}
	}
	var failure *awswire.Error
	selected, failure = selectProtocol(r, selected)
	if failure != nil {
		return selected, failure
	}
	if (selected.Protocol == JSON10 || selected.Protocol == JSON11) && (!hasTarget || prefix != selected.TargetPrefix) {
		return selected, &awswire.Error{Code: "UnknownOperationException", Message: "Target does not match signing service", StatusCode: 400}
	}
	if (selected.Protocol == Query || selected.Protocol == EC2Query) && r.Header.Get("X-Amz-Target") != "" {
		return selected, &awswire.Error{Code: "InvalidAction", Message: "Target does not match Query service", StatusCode: 400}
	}
	return selected, nil
}

func newRequestID() string {
	var value [16]byte
	_, _ = rand.Read(value[:])
	return hex.EncodeToString(value[:])
}

// remoteIP uses the connection peer, never caller-controlled forwarded headers.
// An unparseable peer (for example a Unix socket) has no IP condition context.
func remoteIP(remoteAddr string) string {
	peer, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return ""
	}
	return peer.Addr().Unmap().WithZone("").String()
}
