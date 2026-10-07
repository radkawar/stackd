package apigatewayv2

import (
	"context"
	"crypto/tls"
	"stackd/internal/services/acm"
)

// DomainCertificates resolves immutable ACM identities and current material.
type DomainCertificates interface {
	CertificateID(context.Context, acm.Scope, string) (string, error)
	Certificate(context.Context, acm.Scope, string, string) (tls.Certificate, error)
	CertificateType(context.Context, acm.Scope, string, string) (string, error)
}
type DomainTruststores interface {
	Truststore(context.Context, Scope, string, string) ([]byte, error)
}
type DomainKey struct {
	Scope
	Name string
}
type MappingKey struct {
	DomainKey
	ID string
}
type DomainRecord struct {
	Key                                             DomainKey
	Owner                                           ResourceOwner
	CertificateARN, CertificateID, CertificateName  string
	OwnershipCertificateARN, OwnershipCertificateID string
	SecurityPolicy, IPAddressType                   string
	TruststoreURI, TruststoreVersion                string
	TruststorePEM                                   []byte
	Tags                                            map[string]string
}
type MappingRecord struct {
	Key                MappingKey
	Owner              ResourceOwner
	APIID, Stage, Path string
}
type DomainReader interface {
	Domain(DomainKey) (DomainRecord, error)
	DomainByHost(string) (DomainRecord, error)
	Domains(Scope) ([]DomainRecord, error)
	Mapping(MappingKey) (MappingRecord, error)
	Mappings(DomainKey) ([]MappingRecord, error)
}
type DomainTransaction interface {
	PutDomain(DomainRecord) error
	DeleteDomain(DomainKey) error
	PutMapping(MappingRecord) error
	DeleteMapping(MappingKey) error
}
