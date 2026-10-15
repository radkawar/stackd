package elbv2

import (
	"context"
	"time"

	api "stackd/internal/awsapi/elbv2"
)

// The native HTTP/1 connection lifetime is enforced at the request boundary in
// proxy.go. Other lifetimes remain rejected until per-connection versioned
// settings are durably owned; this is not an arbitrary metadata-only attribute.
const defaultClientKeepAlive = time.Hour

// Only settings with real native effects are admitted as invariants. HTTP2 is
// disabled, and neither WAF nor zonal shift is claimed as enabled. Desync is
// admitted separately, after a fresh probe through the configured native library.
var nativeLoadBalancerAttributes = [...]struct{ key, value string }{
	{"client_keep_alive.seconds", "3600"},
	{"routing.http2.enabled", "false"},
	{"routing.http.drop_invalid_header_fields.enabled", "false"},
	{"routing.http.x_amzn_tls_version_and_cipher_suite.enabled", "false"},
	{"routing.http.xff_client_port.enabled", "false"},
	{"routing.http.xff_header_processing.mode", "append"},
	{"routing.http.preserve_host_header.enabled", "true"},
	{"waf.fail_open.enabled", "false"},
	{"zonal_shift.config.enabled", "false"},
}

func nativeLoadBalancerAttribute(key string) (string, bool) {
	for _, attribute := range nativeLoadBalancerAttributes {
		if attribute.key == key {
			return attribute.value, true
		}
	}
	return "", false
}

func (s *Service) nativeLoadBalancerAttribute(ctx context.Context, key string) (string, bool, error) {
	if key != "routing.http.desync_mitigation_mode" {
		value, implemented := nativeLoadBalancerAttribute(key)
		return value, implemented, nil
	}
	if s.desyncClassifier == nil {
		return "", false, unsupported("Defensive desync mitigation requires a configured genuine http-desync-guardian classifier")
	}
	if err := s.desyncClassifier.Health(ctx); err != nil {
		return "", false, unsupported("Native http-desync-guardian classifier is unavailable: " + err.Error())
	}
	return "defensive", true, nil
}

// The described default is conditional on a healthy classifier with actual
// effects; it must not become a metadata-only entry in the invariant array.
func (s *Service) nativeDesyncAttribute(ctx context.Context) (api.LoadBalancerAttribute, bool, error) {
	if s.desyncClassifier == nil {
		return api.LoadBalancerAttribute{}, false, nil
	}
	expected, implemented, err := s.nativeLoadBalancerAttribute(ctx, "routing.http.desync_mitigation_mode")
	if err != nil {
		return api.LoadBalancerAttribute{}, false, err
	}
	var attribute api.LoadBalancerAttribute
	text(&attribute.Key, "routing.http.desync_mitigation_mode")
	text(&attribute.Value, expected)
	return attribute, implemented, nil
}
