package apigatewayv2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"stackd/internal/services/acm"
	"stackd/internal/services/apigatewayexec"
	"strings"
)

func requestHost(host string) string {
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
func (s *Service) runtimeDomain(ctx context.Context, host string) (DomainRecord, error) {
	var v DomainRecord
	e := s.repository.View(ctx, func(r Reader) error { var err error; v, err = r.DomainByHost(requestHost(host)); return err })
	return v, e
}
func (s *Service) domainCertificate(ctx context.Context, v DomainRecord) (tls.Certificate, error) {
	if s.certificates == nil {
		return tls.Certificate{}, errors.New("API Gateway ACM owner is not configured")
	}
	sc := v.Key.Scope
	pair, err := s.certificates.Certificate(ctx, acm.Scope{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, v.CertificateARN, v.CertificateID)
	if err != nil {
		return pair, err
	}
	if len(pair.Certificate) == 0 {
		return pair, errors.New("API Gateway certificate is empty")
	}
	leaf := pair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return pair, err
		}
	}
	if err = leaf.VerifyHostname(v.Key.Name); err != nil {
		return pair, err
	}
	return pair, nil
}

// DomainTLSConfig resolves live ACM material for owned SNI names. An optional
// fallback serves the ordinary API endpoint, never a failed owned domain.
func (s *Service) DomainTLSConfig(fallback *tls.Config) *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if fallback != nil {
		config = fallback.Clone()
	}
	if config.MinVersion < tls.VersionTLS12 {
		config.MinVersion = tls.VersionTLS12
	}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		v, err := s.runtimeDomain(hello.Context(), hello.ServerName)
		if errors.Is(err, ErrNotFound) && fallback != nil {
			if fallback.GetConfigForClient != nil {
				return fallback.GetConfigForClient(hello)
			}
			return fallback, nil
		}
		if err != nil {
			return nil, err
		}
		pair, err := s.domainCertificate(hello.Context(), v)
		if err != nil {
			return nil, err
		}
		config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}, Time: s.clock.Now}
		if v.TruststoreURI != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(v.TruststorePEM) {
				return nil, errors.New("API Gateway truststore is invalid")
			}
			config.ClientAuth, config.ClientCAs = tls.RequireAndVerifyClientCert, pool
		}
		return config, nil
	}
	return config
}

type WebSocketExecution interface {
	ServeExecution(http.ResponseWriter, *http.Request) bool
}

// DomainDispatcher claims owned hosts only and falls through to the normal
// router for unknown hosts. Host/path binding leaves SigV4 bytes unchanged.
func (s *Service) DomainDispatcher(httpExecution http.Handler, websocket WebSocketExecution, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.ServeDomainExecution(w, r, httpExecution, websocket) {
			next.ServeHTTP(w, r)
		}
	})
}
func (s *Service) ServeDomainExecution(w http.ResponseWriter, r *http.Request, httpExecution http.Handler, websocket WebSocketExecution) bool {
	domain, e := s.runtimeDomain(r.Context(), r.Host)
	if errors.Is(e, ErrNotFound) {
		return false
	}
	if e != nil {
		http.Error(w, "Internal Server Error", 500)
		return true
	}
	if r.TLS == nil || requestHost(r.TLS.ServerName) != domain.Key.Name {
		http.Error(w, "Custom domains require TLS with matching SNI", http.StatusForbidden)
		return true
	}
	if _, err := s.domainCertificate(r.Context(), domain); err != nil {
		http.Error(w, "Domain certificate is unavailable", http.StatusServiceUnavailable)
		return true
	}
	if domain.TruststoreURI != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(domain.TruststorePEM)
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusForbidden)
			return true
		}
		intermediates := x509.NewCertPool()
		for _, cert := range r.TLS.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		if _, err := r.TLS.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, CurrentTime: s.clock.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			http.Error(w, "Untrusted client certificate", http.StatusForbidden)
			return true
		}
	}
	var target apigatewayexec.ExecutionTarget
	e = s.repository.View(r.Context(), func(reader Reader) error {
		rows, e := reader.Mappings(domain.Key)
		if e != nil {
			return e
		}
		var selected *MappingRecord
		path := strings.TrimPrefix(r.URL.Path, "/")
		for i := range rows {
			row := &rows[i]
			if row.Path == "" || path == row.Path || strings.HasPrefix(path, row.Path+"/") {
				if selected == nil || len(row.Path) > len(selected.Path) {
					selected = row
				}
			}
		}
		if selected == nil {
			return ErrNotFound
		}
		api, e := reader.API(APIKey{selected.Key.Scope, selected.APIID})
		if e != nil {
			return e
		}
		if _, e = reader.Stage(ResourceKey{api.Key, selected.Stage}); e != nil {
			return e
		}
		relative := path
		if selected.Path != "" {
			relative = strings.TrimPrefix(strings.TrimPrefix(path, selected.Path), "/")
		}
		target = apigatewayexec.ExecutionTarget{APIID: api.Key.ID, Stage: selected.Stage, Path: "/" + relative}
		return nil
	})
	if e != nil {
		if errors.Is(e, ErrNotFound) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Internal Server Error", 500)
		}
		return true
	}
	r = r.WithContext(apigatewayexec.WithExecutionTarget(r.Context(), target))
	if websocket != nil && websocket.ServeExecution(w, r) {
		return true
	}
	httpExecution.ServeHTTP(w, r)
	return true
}
