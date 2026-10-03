package elbv2

import "crypto/tls"

// This is the admitted ELBSecurityPolicy-TLS13-1-2-Res-2021-06 protocol/cipher set,
// captured by DescribeSSLPolicies. Go chooses suites using its TLS hardware
// preference; it does not implement ALB's documented strict server priority.
// TODO: Comeback reproduce native cipher preference and legacy/PQ/FIPS policies.
func listenerTLSConfig(certificate tls.Certificate) *tls.Config {
	config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}}
	config.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
	return config
}
