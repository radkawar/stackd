package apigatewayexec

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// WebACLs inspects requests to REST API stages with AWS WAF before API Gateway
// authorization, usage plans or integrations run. AWS WAF does not protect HTTP
// or WebSocket APIs.
type WebACLs interface {
	InspectStage(context.Context, WebACLRequest) (WebACLVerdict, error)
}

// WebACLRequest is the request as received by API Gateway for one REST stage.
// URI is the raw (still percent-encoded) path; Header includes Host.
type WebACLRequest struct {
	Partition, AccountID, Region, APIID, Stage string
	Method, URI, RawQuery, Proto, SourceIP     string
	Header                                     http.Header
	Body                                       []byte
}

type WebACLVerdict struct {
	Blocked bool
	// Custom selects the web ACL's CustomResponse instead of WAF_FILTERED.
	Custom      bool
	Status      int
	Headers     http.Header
	Body        []byte
	ContentType string
	// InsertHeaders are added to the request forwarded to the integration.
	InsertHeaders http.Header
}

// inspectWebACL applies the stage's web ACL. It returns the request to
// continue with, or false after writing the WAF block response.
func (s *Handler) inspectWebACL(w http.ResponseWriter, r *http.Request, route *Route, body []byte) (*http.Request, bool) {
	if s.webACLs == nil {
		return r, true
	}
	uri := r.URL.EscapedPath()
	if _, custom := CustomExecutionTarget(r.Context()); !custom {
		_, after, _ := strings.Cut(strings.TrimPrefix(uri, Prefix), "/")
		uri = "/" + after
	}
	header := r.Header.Clone()
	header.Set("Host", r.Host)
	sourceIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		sourceIP = r.RemoteAddr
	}
	verdict, err := s.webACLs.InspectStage(r.Context(), WebACLRequest{
		Partition: route.Partition, AccountID: route.AccountID, Region: route.Region, APIID: route.APIID, Stage: route.Stage,
		Method: r.Method, URI: uri, RawQuery: r.URL.RawQuery, Proto: r.Proto, SourceIP: sourceIP, Header: header, Body: body,
	})
	if err != nil {
		writeIntegrationFailure(w, true)
		return r, false
	}
	if verdict.Blocked {
		if o := requestObservationFrom(r); o != nil {
			o.responseType = "WAF_FILTERED"
		}
		if !verdict.Custom {
			// API Gateway's WAF_FILTERED gateway response: 403 Forbidden.
			w.Header().Set("X-Amzn-ErrorType", "ForbiddenException")
			writeRejection(w, &rejection{http.StatusForbidden, "Forbidden"})
			return r, false
		}
		for name, values := range verdict.Headers {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
		if verdict.ContentType != "" {
			w.Header().Set("Content-Type", verdict.ContentType)
		}
		if recorder, ok := w.(interface{ recordRejection(*rejection) }); ok {
			recorder.recordRejection(&rejection{verdict.Status, string(verdict.Body)})
		}
		w.WriteHeader(verdict.Status)
		_, _ = w.Write(verdict.Body)
		return r, false
	}
	if len(verdict.InsertHeaders) > 0 {
		r = r.Clone(r.Context())
		for name, values := range verdict.InsertHeaders {
			r.Header[http.CanonicalHeaderKey(name)] = values
		}
	}
	return r, true
}
