package acm

import (
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"slices"
	api "stackd/internal/awsapi/acm"
	"strings"
)

func validationProjection(c CertificateRecord) api.DomainValidationList {
	out := api.DomainValidationList{}
	for _, v := range c.Validations {
		out = append(out, api.DomainValidation{DomainName: new(api.DomainNameString(v.Domain)), ValidationMethod: new(api.ValidationMethod("DNS")), ValidationStatus: new(api.DomainStatus(v.Status)), ResourceRecord: &api.ResourceRecord{Name: new(api.String(v.Name)), Value: new(api.String(v.Value)), Type: new(api.RecordType("CNAME"))}})
	}
	return out
}
func domainsProjection(c CertificateRecord) api.DomainList {
	out := api.DomainList{}
	for _, v := range c.Validations {
		out = append(out, api.DomainNameString(v.Domain))
	}
	return out
}
func keyPairOrigin(c CertificateRecord) api.CertificateKeyPairOrigin {
	if c.Type == "IMPORTED" {
		return api.CertificateKeyPairOriginCUSTOMER_PROVIDED
	}
	return api.CertificateKeyPairOriginAWS_MANAGED
}
func parseLeaf(c CertificateRecord) (*x509.Certificate, error) {
	block, _ := pem.Decode(c.CertificatePEM)
	if block == nil {
		return nil, failure("InvalidStateException", "Certificate material is unavailable.")
	}
	return x509.ParseCertificate(block.Bytes)
}
func (s *Service) eligible(c CertificateRecord, users []string) bool {
	return c.Type == "AMAZON_ISSUED" && s.currentStatus(c) == "ISSUED" && (c.Exported || len(users) > 0)
}
func (s *Service) detail(r Reader, c CertificateRecord) (*api.CertificateDetail, error) {
	users, e := s.users(r, c)
	if e != nil {
		return nil, e
	}
	d := &api.CertificateDetail{CertificateArn: new(api.Arn(c.ARN)), DomainName: new(api.DomainNameString(c.Domain)), Status: new(api.CertificateStatus(s.currentStatus(c))), Type: new(api.CertificateType(c.Type)), KeyAlgorithm: new(api.KeyAlgorithm(c.KeyAlgorithm)), CreatedAt: &c.Created, SubjectAlternativeNames: domainsProjection(c), InUseBy: api.InUseList{}, Options: &api.CertificateOptions{Export: new(api.CertificateExport(c.ExportOption)), CertificateTransparencyLoggingPreference: new(api.CertificateTransparencyLoggingPreference(c.Transparency))}, RenewalEligibility: new(api.RenewalEligibility("INELIGIBLE"))}
	d.CertificateKeyPairOrigin = new(keyPairOrigin(c))
	for _, u := range users {
		d.InUseBy = append(d.InUseBy, api.String(u))
	}
	if s.eligible(c, users) {
		d.RenewalEligibility = new(api.RenewalEligibility("ELIGIBLE"))
	}
	if c.Type == "AMAZON_ISSUED" {
		d.DomainValidationOptions = validationProjection(c)
	}
	if c.RenewalStatus != "" {
		d.RenewalSummary = &api.RenewalSummary{RenewalStatus: new(api.RenewalStatus(c.RenewalStatus)), UpdatedAt: &c.RenewalUpdated, DomainValidationOptions: validationProjection(c)}
	}
	if len(c.CertificatePEM) > 0 {
		leaf, e := parseLeaf(c)
		if e != nil {
			return nil, e
		}
		d.NotBefore = &c.NotBefore
		d.NotAfter = &c.NotAfter
		d.Serial = new(api.String(leaf.SerialNumber.Text(16)))
		d.Subject = new(api.String(leaf.Subject.String()))
		d.Issuer = new(api.String(leaf.Issuer.String()))
		d.SignatureAlgorithm = new(api.String(leaf.SignatureAlgorithm.String()))
		d.KeyUsages = keyUsages(leaf)
		d.ExtendedKeyUsages = extendedUsages(leaf)
		if c.Type == "IMPORTED" {
			d.ImportedAt = &c.Imported
		} else {
			d.IssuedAt = &c.Issued
		}
	}
	return d, nil
}
func keyUsages(c *x509.Certificate) api.KeyUsageList {
	out := api.KeyUsageList{}
	for _, v := range []struct {
		bit  x509.KeyUsage
		name string
	}{{x509.KeyUsageDigitalSignature, "DIGITAL_SIGNATURE"}, {x509.KeyUsageContentCommitment, "NON_REPUDIATION"}, {x509.KeyUsageKeyEncipherment, "KEY_ENCIPHERMENT"}, {x509.KeyUsageDataEncipherment, "DATA_ENCIPHERMENT"}, {x509.KeyUsageKeyAgreement, "KEY_AGREEMENT"}, {x509.KeyUsageCertSign, "CERTIFICATE_SIGNING"}, {x509.KeyUsageCRLSign, "CRL_SIGNING"}, {x509.KeyUsageEncipherOnly, "ENCIPHER_ONLY"}, {x509.KeyUsageDecipherOnly, "DECIPHER_ONLY"}} {
		if c.KeyUsage&v.bit != 0 {
			out = append(out, api.KeyUsage{Name: new(api.KeyUsageName(v.name))})
		}
	}
	return out
}
func extendedUsages(c *x509.Certificate) api.ExtendedKeyUsageList {
	out := api.ExtendedKeyUsageList{}
	for _, v := range c.ExtKeyUsage {
		var name, oid string
		switch v {
		case x509.ExtKeyUsageServerAuth:
			name, oid = "TLS_WEB_SERVER_AUTHENTICATION", "1.3.6.1.5.5.7.3.1"
		case x509.ExtKeyUsageClientAuth:
			name, oid = "TLS_WEB_CLIENT_AUTHENTICATION", "1.3.6.1.5.5.7.3.2"
		case x509.ExtKeyUsageCodeSigning:
			name, oid = "CODE_SIGNING", "1.3.6.1.5.5.7.3.3"
		case x509.ExtKeyUsageEmailProtection:
			name, oid = "EMAIL_PROTECTION", "1.3.6.1.5.5.7.3.4"
		case x509.ExtKeyUsageTimeStamping:
			name, oid = "TIME_STAMPING", "1.3.6.1.5.5.7.3.8"
		case x509.ExtKeyUsageOCSPSigning:
			name, oid = "OCSP_SIGNING", "1.3.6.1.5.5.7.3.9"
		case x509.ExtKeyUsageAny:
			name, oid = "ANY", "2.5.29.37.0"
		default:
			name = "CUSTOM"
		}
		out = append(out, api.ExtendedKeyUsage{Name: new(api.ExtendedKeyUsageName(name)), OID: new(api.String(oid))})
	}
	for _, oid := range c.UnknownExtKeyUsage {
		out = append(out, api.ExtendedKeyUsage{Name: new(api.ExtendedKeyUsageName("CUSTOM")), OID: new(api.String(oid.String()))})
	}
	return out
}
func (s *Service) describeCertificate(tx Transaction, in *api.DescribeCertificateRequest) (*api.DescribeCertificateResponse, error) {
	var c CertificateRecord
	var e error
	arn := value(in.CertificateArn)
	if arn == "" && cloudFormationOwner(tx.Context()) != "" {
		// Trusted exact-incarnation recovery resolves only private native authority.
		c, e = tx.CertificateByOwner(scopeFor(tx.Context()), cloudFormationOwner(tx.Context()))
		if e == nil {
			e = s.authorize(tx, "DescribeCertificate", c.ARN, c.Tags, nil)
		}
		if e == nil {
			e = observeCloudFormationOwner(tx.Context(), c)
		}
	} else {
		c, e = s.owned(tx, "DescribeCertificate", arn)
	}
	if e != nil {
		return nil, e
	}
	d, e := s.detail(tx, c)
	return &api.DescribeCertificateResponse{Certificate: d}, e
}
func (s *Service) listCertificates(tx Transaction, in *api.ListCertificatesRequest) (*api.ListCertificatesResponse, error) {
	if e := s.authorize(tx, "ListCertificates", "", nil, nil); e != nil {
		return nil, e
	}
	limit := 100
	if in.MaxItems != nil {
		limit = int(*in.MaxItems)
	}
	if limit < 1 || limit > 1000 {
		return nil, failure("InvalidArgsException", "MaxItems must be between 1 and 1000.")
	}
	if (in.SortBy == nil) != (in.SortOrder == nil) {
		return nil, failure("InvalidArgsException", "SortBy and SortOrder must be specified together.")
	}
	if value(in.SortBy) != "" && value(in.SortBy) != "CREATED_AT" {
		return nil, failure("InvalidArgsException", "Unsupported SortBy.")
	}
	if value(in.SortOrder) != "" && value(in.SortOrder) != "ASCENDING" && value(in.SortOrder) != "DESCENDING" {
		return nil, failure("InvalidArgsException", "Unsupported SortOrder.")
	}
	scope := scopeFor(tx.Context())
	filter := *in
	filter.NextToken = nil
	filter.MaxItems = nil
	encoded, _ := json.Marshal(struct {
		Scope  Scope
		Filter api.ListCertificatesRequest
	}{scope, filter})
	hash := sha256.Sum256(encoded)
	prefix := hex.EncodeToString(hash[:]) + ":"
	after := ""
	if in.NextToken != nil {
		decoded, e := base64.RawURLEncoding.DecodeString(value(in.NextToken))
		if e != nil || !strings.HasPrefix(string(decoded), prefix) {
			return nil, failure("InvalidArgsException", "Invalid pagination token.")
		}
		after = strings.TrimPrefix(string(decoded), prefix)
	}
	records, e := tx.Certificates()
	if e != nil {
		return nil, e
	}
	slices.SortFunc(records, func(a, b CertificateRecord) int {
		n := a.Created.Compare(b.Created)
		if n == 0 {
			n = cmp.Compare(a.ARN, b.ARN)
		}
		if value(in.SortOrder) == "DESCENDING" {
			n = -n
		}
		return n
	})
	out := &api.ListCertificatesResponse{CertificateSummaryList: api.CertificateSummaryList{}}
	started := after == ""
	last := ""
	for _, c := range records {
		if c.Scope != scope {
			continue
		}
		if !started {
			if c.ARN == after {
				started = true
			}
			continue
		}
		status := api.CertificateStatus(s.currentStatus(c))
		if len(in.CertificateStatuses) > 0 && !slices.Contains(in.CertificateStatuses, status) {
			continue
		}
		origin := keyPairOrigin(c)
		if len(in.CertificateKeyPairOrigins) > 0 && !slices.Contains(in.CertificateKeyPairOrigins, origin) {
			continue
		}
		keys := api.KeyAlgorithmList{api.KeyAlgorithm("RSA_2048")}
		if in.Includes != nil && len(in.Includes.KeyTypes) > 0 {
			keys = in.Includes.KeyTypes
		}
		if !slices.Contains(keys, api.KeyAlgorithm(c.KeyAlgorithm)) {
			continue
		}
		d, e := s.detail(tx, c)
		if e != nil {
			return nil, e
		}
		if in.Includes != nil {
			f := in.Includes
			if value(f.ExportOption) != "" && value(f.ExportOption) != c.ExportOption {
				continue
			}
			if value(f.ManagedBy) != "" {
				continue
			}
			if !matchesKeyUsages(f.KeyUsage, d.KeyUsages) || !matchesExtendedUsages(f.ExtendedKeyUsage, d.ExtendedKeyUsages) {
				continue
			}
		}
		if len(out.CertificateSummaryList) == limit {
			out.NextToken = new(api.NextToken(base64.RawURLEncoding.EncodeToString([]byte(prefix + last))))
			break
		}
		summary := api.CertificateSummary{CertificateArn: d.CertificateArn, DomainName: d.DomainName, Status: d.Status, Type: d.Type, CreatedAt: d.CreatedAt, IssuedAt: d.IssuedAt, ImportedAt: d.ImportedAt, NotBefore: d.NotBefore, NotAfter: d.NotAfter, KeyAlgorithm: d.KeyAlgorithm, RenewalEligibility: d.RenewalEligibility, InUse: new(api.NullableBoolean(len(d.InUseBy) > 0)), Exported: new(api.NullableBoolean(c.Exported)), ExportOption: new(api.CertificateExport(c.ExportOption)), SubjectAlternativeNameSummaries: d.SubjectAlternativeNames, HasAdditionalSubjectAlternativeNames: new(api.NullableBoolean(false))}
		summary.CertificateKeyPairOrigin = d.CertificateKeyPairOrigin
		for _, u := range d.KeyUsages {
			summary.KeyUsages = append(summary.KeyUsages, *u.Name)
		}
		for _, u := range d.ExtendedKeyUsages {
			summary.ExtendedKeyUsages = append(summary.ExtendedKeyUsages, *u.Name)
		}
		out.CertificateSummaryList = append(out.CertificateSummaryList, summary)
		last = c.ARN
	}
	if !started {
		return nil, failure("InvalidArgsException", "Pagination certificate is no longer available.")
	}
	return out, nil
}
func matchesKeyUsages(filter api.KeyUsageFilterList, usages api.KeyUsageList) bool {
	if len(filter) == 0 {
		return true
	}
	for _, f := range filter {
		for _, u := range usages {
			if string(f) == value(u.Name) {
				return true
			}
		}
	}
	return false
}
func matchesExtendedUsages(filter api.ExtendedKeyUsageFilterList, usages api.ExtendedKeyUsageList) bool {
	if len(filter) == 0 {
		return true
	}
	for _, f := range filter {
		for _, u := range usages {
			if string(f) == value(u.Name) {
				return true
			}
		}
	}
	return false
}
