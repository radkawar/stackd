package apigatewayv2

import (
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	api "stackd/internal/awsapi/apigatewayv2"
	"stackd/internal/services/acm"
	"strings"
)

func registerDomains(s *Service) {
	register(s, "CreateDomainName", s.createDomain)
	register(s, "GetDomainName", s.getDomain)
	register(s, "GetDomainNames", s.getDomains)
	register(s, "UpdateDomainName", s.updateDomain)
	register(s, "DeleteDomainName", s.deleteDomain)
	register(s, "CreateApiMapping", s.createMapping)
	register(s, "GetApiMapping", s.getMapping)
	register(s, "GetApiMappings", s.getMappings)
	register(s, "UpdateApiMapping", s.updateMapping)
	register(s, "DeleteApiMapping", s.deleteMapping)
}
func domainNameValid(name string) bool {
	if name == "" || len(name) > 253 || name != strings.ToLower(name) || net.ParseIP(name) != nil {
		return false
	}
	for _, part := range strings.Split(name, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func domainOwner(r Reader, owner ResourceOwner) error {
	if requested, ok := ResourceOwnerFromContext(r.Context()); ok && requested != owner {
		return failure("ConflictException", "Resource is not owned by this CloudFormation resource", 409)
	}
	return nil
}
func (s *Service) ownedDomain(r Reader, method, name, suffix string) (DomainRecord, error) {
	v, e := r.Domain(DomainKey{scopeFor(r.Context()), name})
	if e != nil && !errors.Is(e, ErrNotFound) {
		return v, e
	}
	if a := s.authorize(r, method, "/domainnames/"+name+suffix, v.Tags, nil, nil); a != nil {
		return v, a
	}
	return v, e
}
func (s *Service) domainConfiguration(tx Transaction, v *DomainRecord, configs api.DomainNameConfigurations, mtls *api.MutualTlsAuthenticationInput, mode string) error {
	if mode != "" && mode != "API_MAPPING_ONLY" {
		return unsupported("Only API_MAPPING_ONLY routing is implemented")
	}
	if len(configs) != 1 {
		return bad("Exactly one REGIONAL domain configuration is required")
	}
	c := configs[0]
	if value(c.EndpointType) != "" && value(c.EndpointType) != "REGIONAL" {
		return bad("V2 custom domains require REGIONAL endpoints")
	}
	if value(c.SecurityPolicy) != "" && value(c.SecurityPolicy) != "TLS_1_2" {
		return bad("V2 custom domains require TLS_1_2")
	}
	if value(c.IpAddressType) != "" && value(c.IpAddressType) != "ipv4" {
		return unsupported("The execution listener supports ipv4 domains")
	}
	if c.ApiGatewayDomainName != nil || c.HostedZoneId != nil || c.DomainNameStatus != nil || c.DomainNameStatusMessage != nil || c.CertificateUploadDate != nil {
		return bad("Domain endpoint and status fields are read-only")
	}
	arn := value(c.CertificateArn)
	sc := v.Key.Scope
	if !strings.HasPrefix(arn, "arn:"+sc.Partition+":acm:"+sc.Region+":"+sc.AccountID+":certificate/") || s.certificates == nil {
		return bad("An issued ACM certificate in the domain account and region is required")
	}
	scope := acm.Scope{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}
	id := v.CertificateID
	var e error
	if arn != v.CertificateARN || id == "" {
		id, e = s.certificates.CertificateID(tx.Context(), scope, arn)
		if e != nil || id == "" {
			return bad("Certificate is not available from ACM")
		}
	}
	cert, e := s.certificates.Certificate(tx.Context(), scope, arn, id)
	if e != nil || len(cert.Certificate) == 0 {
		return bad("Certificate material is unavailable")
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil || leaf.VerifyHostname(v.Key.Name) != nil {
		return bad("Certificate does not cover the domain name")
	}
	v.CertificateARN, v.CertificateID, v.CertificateName = arn, id, value(c.CertificateName)
	v.SecurityPolicy, v.IPAddressType = "TLS_1_2", "ipv4"
	proofARN := value(c.OwnershipVerificationCertificateArn)
	proofID := v.OwnershipCertificateID
	if proofARN != "" {
		if proofARN != v.OwnershipCertificateARN || proofID == "" {
			proofID, e = s.certificates.CertificateID(tx.Context(), scope, proofARN)
			if e != nil {
				return bad("Ownership verification certificate is unavailable")
			}
		}
		pair, err := s.certificates.Certificate(tx.Context(), scope, proofARN, proofID)
		if err != nil || len(pair.Certificate) == 0 {
			return bad("Ownership verification certificate is unavailable")
		}
		proof, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || proof.VerifyHostname(v.Key.Name) != nil {
			return bad("Ownership verification certificate does not cover domain")
		}
	} else {
		proofID = ""
	}
	v.OwnershipCertificateARN, v.OwnershipCertificateID = proofARN, proofID
	if mtls != nil {
		v.TruststoreURI, v.TruststoreVersion = value(mtls.TruststoreUri), value(mtls.TruststoreVersion)
		v.TruststorePEM = nil
		if v.TruststoreURI != "" {
			u, err := url.Parse(v.TruststoreURI)
			if err != nil || u.Scheme != "s3" || u.Host == "" || u.Path == "" || u.RawQuery != "" || u.Fragment != "" {
				return bad("TruststoreUri must identify an S3 object")
			}
			if s.truststores == nil {
				return unsupported("S3 truststore owner is not configured")
			}
			v.TruststorePEM, e = s.truststores.Truststore(tx.Context(), sc, v.TruststoreURI, v.TruststoreVersion)
			if e != nil {
				return e
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(v.TruststorePEM) {
				return bad("Truststore contains no PEM certificates")
			}
		} else if v.TruststoreVersion != "" {
			return bad("TruststoreVersion requires TruststoreUri")
		}
	}
	if v.TruststoreURI != "" {
		kind, err := s.certificates.CertificateType(tx.Context(), scope, v.CertificateARN, v.CertificateID)
		if err != nil {
			return bad("Certificate provenance is unavailable")
		}
		if kind != "AMAZON_ISSUED" && v.OwnershipCertificateARN == "" {
			return bad("Mutual TLS with imported or private certificates requires a public ownership verification certificate")
		}
	}
	if v.OwnershipCertificateARN != "" {
		kind, err := s.certificates.CertificateType(tx.Context(), scope, v.OwnershipCertificateARN, v.OwnershipCertificateID)
		if err != nil || kind != "AMAZON_ISSUED" {
			return bad("Ownership verification requires a public ACM certificate")
		}
	}
	return nil
}
func (s *Service) domainOutput(v DomainRecord) api.DomainName {
	out := api.DomainName{}
	text(&out.DomainName, v.Key.Name)
	text(&out.DomainNameArn, controlARN(v.Key.Scope, "/domainnames/"+v.Key.Name))
	text(&out.ApiMappingSelectionExpression, "$request.basepath")
	text(&out.RoutingMode, "API_MAPPING_ONLY")
	stringMap(&out.Tags, v.Tags)
	c := api.DomainNameConfiguration{}
	text(&c.CertificateArn, v.CertificateARN)
	text(&c.EndpointType, "REGIONAL")
	text(&c.SecurityPolicy, v.SecurityPolicy)
	text(&c.IpAddressType, v.IPAddressType)
	text(&c.DomainNameStatus, "AVAILABLE")
	// This is the real emulator execution authority, not an invented AWS endpoint or hosted zone.
	if u, e := url.Parse(s.endpoint); e == nil && u.Host != "" {
		text(&c.ApiGatewayDomainName, u.Host)
	}
	if v.CertificateName != "" {
		text(&c.CertificateName, v.CertificateName)
	}
	if v.OwnershipCertificateARN != "" {
		text(&c.OwnershipVerificationCertificateArn, v.OwnershipCertificateARN)
	}
	out.DomainNameConfigurations = api.DomainNameConfigurations{c}
	if v.TruststoreURI != "" {
		out.MutualTlsAuthentication = &api.MutualTlsAuthentication{}
		text(&out.MutualTlsAuthentication.TruststoreUri, v.TruststoreURI)
		if v.TruststoreVersion != "" {
			text(&out.MutualTlsAuthentication.TruststoreVersion, v.TruststoreVersion)
		}
	}
	return out
}
func (s *Service) createDomain(tx Transaction, in *api.CreateDomainNameInput) (*api.CreateDomainNameOutput, error) {
	if e := s.authorize(tx, "POST", "/domainnames", nil, mapOf(in.Tags), nil); e != nil {
		return nil, e
	}
	name := value(in.DomainName)
	if !domainNameValid(name) {
		return nil, bad("DomainName must be a lowercase DNS name")
	}
	if e := validTags(mapOf(in.Tags)); e != nil {
		return nil, e
	}
	k := DomainKey{scopeFor(tx.Context()), name}
	existing, e := tx.Domain(k)
	if e == nil {
		if owner, ok := ResourceOwnerFromContext(tx.Context()); ok && owner == existing.Owner {
			return new(api.CreateDomainNameOutput(s.domainOutput(existing))), nil
		}
		return nil, failure("ConflictException", "Domain name already exists", 409)
	}
	if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	if _, err := tx.DomainByHost(name); err == nil {
		return nil, failure("ConflictException", "Domain name already exists", 409)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	v := DomainRecord{Key: k, Tags: mapOf(in.Tags)}
	v.Owner, _ = ResourceOwnerFromContext(tx.Context())
	if e = s.domainConfiguration(tx, &v, in.DomainNameConfigurations, in.MutualTlsAuthentication, value(in.RoutingMode)); e != nil {
		return nil, e
	}
	if e = tx.PutDomain(v); e != nil {
		return nil, e
	}
	return new(api.CreateDomainNameOutput(s.domainOutput(v))), nil
}
func (s *Service) getDomain(tx Transaction, in *api.GetDomainNameInput) (*api.GetDomainNameOutput, error) {
	v, e := s.ownedDomain(tx, "GET", value(in.DomainName), "")
	if e != nil {
		return nil, e
	}
	return new(api.GetDomainNameOutput(s.domainOutput(v))), nil
}
func (s *Service) getDomains(tx Transaction, in *api.GetDomainNamesInput) (*api.GetDomainNamesOutput, error) {
	if e := s.authorize(tx, "GET", "/domainnames", nil, nil, nil); e != nil {
		return nil, e
	}
	rows, e := tx.Domains(scopeFor(tx.Context()))
	if e != nil {
		return nil, e
	}
	rows, next, e := page(rows, value(in.MaxResults), value(in.NextToken), pageBinding(tx, "/domainnames"), func(v DomainRecord) string { return v.Key.Name })
	if e != nil {
		return nil, e
	}
	out := &api.GetDomainNamesOutput{}
	for _, v := range rows {
		out.Items = append(out.Items, s.domainOutput(v))
	}
	if out.Items == nil {
		out.Items = []api.DomainName{}
	}
	if next != nil {
		text(&out.NextToken, *next)
	}
	return out, nil
}
func (s *Service) updateDomain(tx Transaction, in *api.UpdateDomainNameInput) (*api.UpdateDomainNameOutput, error) {
	v, e := s.ownedDomain(tx, "PATCH", value(in.DomainName), "")
	if e != nil {
		return nil, e
	}
	if e = domainOwner(tx, v.Owner); e != nil {
		return nil, e
	}
	configs := in.DomainNameConfigurations
	if configs == nil {
		configs = s.domainOutput(v).DomainNameConfigurations
		configs[0].ApiGatewayDomainName = nil
		configs[0].DomainNameStatus = nil
	}
	if e = s.domainConfiguration(tx, &v, configs, in.MutualTlsAuthentication, value(in.RoutingMode)); e != nil {
		return nil, e
	}
	if e = tx.PutDomain(v); e != nil {
		return nil, e
	}
	return new(api.UpdateDomainNameOutput(s.domainOutput(v))), nil
}
func (s *Service) deleteDomain(tx Transaction, in *api.DeleteDomainNameInput) (*api.DeleteDomainNameOutput, error) {
	v, e := s.ownedDomain(tx, "DELETE", value(in.DomainName), "")
	if e != nil {
		return nil, e
	}
	if e = domainOwner(tx, v.Owner); e != nil {
		return nil, e
	}
	if e = tx.DeleteDomain(v.Key); e != nil {
		return nil, e
	}
	return &api.DeleteDomainNameOutput{}, nil
}
