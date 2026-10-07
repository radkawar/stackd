package acm

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"golang.org/x/net/idna"
	"net"
	"slices"
	api "stackd/internal/awsapi/acm"
	"strings"
	"time"
)

const validationTimeout = 72 * time.Hour
const certificateLifetime = 198 * 24 * time.Hour
const renewalWindow = 45 * 24 * time.Hour
const validationPoll = time.Minute

func domainName(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(raw, "."))
	base := strings.TrimPrefix(d, "*.")
	if len(d) > 253 || len(base) == 0 || !strings.Contains(base, ".") || net.ParseIP(base) != nil {
		return "", failure("InvalidDomainValidationOptionsException", "A fully qualified DNS domain is required.")
	}
	ascii, e := idna.Lookup.ToASCII(base)
	if e != nil || ascii != base {
		return "", failure("InvalidDomainValidationOptionsException", "Use a valid ASCII or punycode domain.")
	}
	for _, label := range strings.Split(base, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || (len(label) >= 4 && label[2:4] == "--" && !strings.HasPrefix(label, "xn--")) {
			return "", failure("InvalidDomainValidationOptionsException", "Invalid DNS label.")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", failure("InvalidDomainValidationOptionsException", "Invalid DNS domain.")
			}
		}
	}
	return d, nil
}
func randomToken() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func tagsFrom(in api.TagList) (map[string]string, error) {
	out := map[string]string{}
	for _, t := range in {
		k := value(t.Key)
		if k == "" || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, failure("InvalidTagException", "Invalid tag key.")
		}
		out[k] = value(t.Value)
	}
	if len(out) > 50 {
		return nil, failure("TooManyTagsException", "A certificate supports at most 50 tags.")
	}
	return out, nil
}
func (s *Service) requestCertificate(tx Transaction, in *api.RequestCertificateRequest) (*api.RequestCertificateResponse, error) {
	if e := s.authorize(tx, "RequestCertificate", "", nil, in.Tags); e != nil {
		return nil, e
	}
	if value(in.CertificateAuthorityArn) != "" || value(in.ManagedBy) != "" {
		return nil, failure("InvalidParameterException", "Private CA and managed certificate requests are not supported.")
	}
	if value(in.ValidationMethod) != "DNS" {
		return nil, failure("InvalidParameterException", "Only DNS validation is supported; specify ValidationMethod DNS.")
	}
	if s.dns == nil {
		return nil, failure("InvalidParameterException", "DNS validation requires the configured public DNS resolver.")
	}
	if len(in.DomainValidationOptions) > 0 {
		return nil, failure("InvalidDomainValidationOptionsException", "DomainValidationOptions applies to email validation.")
	}
	algorithm := value(in.KeyAlgorithm)
	if algorithm == "" {
		algorithm = "RSA_2048"
	}
	if algorithm != "RSA_2048" && algorithm != "EC_prime256v1" && algorithm != "EC_secp384r1" {
		return nil, failure("InvalidParameterException", "Unsupported request key algorithm.")
	}
	export, ct := "DISABLED", "ENABLED"
	if in.Options != nil {
		if value(in.Options.Export) != "" {
			export = value(in.Options.Export)
		}
		if value(in.Options.CertificateTransparencyLoggingPreference) != "" {
			ct = value(in.Options.CertificateTransparencyLoggingPreference)
		}
		if value(in.Options.ValidationMethod) != "" && value(in.Options.ValidationMethod) != "DNS" {
			return nil, failure("InvalidParameterException", "Only DNS validation is supported.")
		}
	}
	if (export != "ENABLED" && export != "DISABLED") || (ct != "ENABLED" && ct != "DISABLED") {
		return nil, failure("InvalidParameterException", "Invalid certificate options.")
	}
	domain, e := domainName(value(in.DomainName))
	if e != nil {
		return nil, e
	}
	domains := []string{domain}
	for _, d := range in.SubjectAlternativeNames {
		normalized, e := domainName(string(d))
		if e != nil {
			return nil, e
		}
		if !slices.Contains(domains, normalized) {
			domains = append(domains, normalized)
		}
	}
	if len(domains) > 10 {
		return nil, failure("LimitExceededException", "A certificate supports at most 10 domain names.")
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	scope := scopeFor(tx.Context())
	now := s.clock.Now()
	token := value(in.IdempotencyToken)
	owner := cloudFormationOwner(tx.Context())
	if owner != "" {
		c, e := tx.CertificateByOwner(scope, owner)
		if e == nil {
			if e = observeCloudFormationOwner(tx.Context(), c); e != nil {
				return nil, e
			}
			if !matchesCertificateRequest(c, domain, domains, algorithm, export) {
				return nil, failure("InvalidParameterException", "This incarnation was admitted with different certificate properties.")
			}
			return &api.RequestCertificateResponse{CertificateArn: new(api.Arn(c.ARN))}, nil
		}
		if !errors.Is(e, ErrNotFound) {
			return nil, e
		}
	}
	if token != "" {
		r, e := tx.Receipt(scope, token)
		if e == nil && now.Before(r.Expires) {
			c, lookupErr := tx.Certificate(r.ARN)
			if lookupErr == nil {
				if e = observeCloudFormationOwner(tx.Context(), c); e != nil {
					return nil, e
				}
				if owner != "" && !matchesCertificateRequest(c, domain, domains, algorithm, export) {
					return nil, failure("InvalidParameterException", "Idempotency token identifies a different certificate request.")
				}
				return &api.RequestCertificateResponse{CertificateArn: new(api.Arn(r.ARN))}, nil
			}
			if !errors.Is(lookupErr, ErrNotFound) {
				return nil, lookupErr
			}
		} else if e != nil && !errors.Is(e, ErrNotFound) {
			return nil, e
		}
	}
	id := uuid.NewString()
	c := CertificateRecord{Scope: scope, ARN: "arn:" + scope.Partition + ":acm:" + scope.Region + ":" + scope.AccountID + ":certificate/" + id, ID: id, Domain: domain, Status: "PENDING_VALIDATION", Type: "AMAZON_ISSUED", KeyAlgorithm: algorithm, Transparency: ct, ExportOption: export, Created: now, ValidationDeadline: now.Add(validationTimeout), NextCheck: now, Version: 1, Tags: tags}
	c.Owner = owner
	for _, d := range domains {
		base := strings.TrimPrefix(d, "*.")
		t, e := tx.Token(scope.Partition, scope.AccountID, base)
		if errors.Is(e, ErrNotFound) {
			a, err := randomToken()
			if err != nil {
				return nil, err
			}
			b, err := randomToken()
			if err != nil {
				return nil, err
			}
			t = ValidationToken{scope.Partition, scope.AccountID, base, "_" + a + "." + base + ".", "_" + b + ".acm-validations.aws."}
			e = tx.PutToken(t)
		}
		if e != nil {
			return nil, e
		}
		c.Validations = append(c.Validations, Validation{d, t.Name, t.Value, "PENDING_VALIDATION"})
	}
	if e = tx.PutCertificate(c); e != nil {
		return nil, e
	}
	if token != "" {
		if e = tx.PutReceipt(Receipt{scope, token, c.ARN, now.Add(time.Hour)}); e != nil {
			return nil, e
		}
	}
	return &api.RequestCertificateResponse{CertificateArn: new(api.Arn(c.ARN))}, nil
}

func matchesCertificateRequest(c CertificateRecord, domain string, domains []string, algorithm, export string) bool {
	if c.Domain != domain || c.Type != "AMAZON_ISSUED" || c.KeyAlgorithm != algorithm || c.ExportOption != export || len(c.Validations) != len(domains) {
		return false
	}
	for _, v := range c.Validations {
		if !slices.Contains(domains, v.Domain) {
			return false
		}
	}
	return true
}
func (s *Service) currentStatus(c CertificateRecord) string {
	now := s.clock.Now()
	if c.Status == "PENDING_VALIDATION" && !now.Before(c.ValidationDeadline) {
		return "VALIDATION_TIMED_OUT"
	}
	if c.Status == "ISSUED" && !now.Before(c.NotAfter) {
		return "EXPIRED"
	}
	return c.Status
}
func (s *Service) deleteCertificate(tx Transaction, in *api.DeleteCertificateRequest) (*api.Unit, error) {
	c, e := s.owned(tx, "DeleteCertificate", value(in.CertificateArn))
	if e != nil {
		return nil, e
	}
	users, e := s.users(tx, c)
	if e != nil {
		return nil, e
	}
	if len(users) > 0 {
		return nil, failure("ResourceInUseException", "Certificate is associated with another service.")
	}
	if e = tx.DeleteCertificate(c.ARN); e != nil {
		return nil, e
	}
	s.mu.Lock()
	delete(s.cache, c.ID)
	s.mu.Unlock()
	return &api.Unit{}, nil
}
func (s *Service) getCertificate(tx Transaction, in *api.GetCertificateRequest) (*api.GetCertificateResponse, error) {
	c, e := s.owned(tx, "GetCertificate", value(in.CertificateArn))
	if e != nil {
		return nil, e
	}
	if len(c.CertificatePEM) == 0 {
		return nil, failure("RequestInProgressException", "Certificate has not been issued.")
	}
	return &api.GetCertificateResponse{Certificate: new(api.CertificateBody(c.CertificatePEM)), CertificateChain: new(api.CertificateChain(c.ChainPEM))}, nil
}
func (s *Service) renewCertificate(tx Transaction, in *api.RenewCertificateRequest) (*api.Unit, error) {
	c, e := s.owned(tx, "RenewCertificate", value(in.CertificateArn))
	if e != nil {
		return nil, e
	}
	if c.Status == "PENDING_VALIDATION" {
		return nil, failure("RequestInProgressException", "Certificate has not been issued.")
	}
	if c.Type != "AMAZON_ISSUED" || !c.Exported || s.currentStatus(c) != "ISSUED" {
		return nil, failure("ValidationException", "Manual renewal requires an issued, exported ACM certificate.")
	}
	c.RenewalStatus = "PENDING_AUTO_RENEWAL"
	c.RenewalUpdated = s.clock.Now()
	c.NextCheck = s.clock.Now()
	c.Version++
	return &api.Unit{}, tx.PutCertificate(c)
}
func (s *Service) updateOptions(tx Transaction, in *api.UpdateCertificateOptionsRequest) (*api.Unit, error) {
	c, e := s.owned(tx, "UpdateCertificateOptions", value(in.CertificateArn))
	if e != nil {
		return nil, e
	}
	if in.Options == nil {
		return nil, failure("ValidationException", "Options are required.")
	}
	if value(in.Options.Export) != "" && value(in.Options.Export) != c.ExportOption {
		return nil, failure("ValidationException", "Exportability cannot be changed after request.")
	}
	if value(in.Options.ValidationMethod) != "" && value(in.Options.ValidationMethod) != "DNS" {
		return nil, failure("ValidationException", "Only DNS validation is supported.")
	}
	if ct := value(in.Options.CertificateTransparencyLoggingPreference); ct != "" {
		if ct != "ENABLED" && ct != "DISABLED" {
			return nil, failure("ValidationException", "Invalid transparency option.")
		}
		c.Transparency = ct
	}
	c.Version++
	return &api.Unit{}, tx.PutCertificate(c)
}
func (s *Service) addTags(tx Transaction, in *api.AddTagsToCertificateRequest) (*api.Unit, error) {
	c, e := s.owned(tx, "AddTagsToCertificate", value(in.CertificateArn))
	if e != nil {
		return nil, e
	}
	tags, e := tagsFrom(in.Tags)
	if e != nil {
		return nil, e
	}
	for k, v := range tags {
		c.Tags[k] = v
	}
	if len(c.Tags) > 50 {
		return nil, failure("TooManyTagsException", "A certificate supports at most 50 tags.")
	}
	c.Version++
	return &api.Unit{}, tx.PutCertificate(c)
}
func (s *Service) removeTags(tx Transaction, in *api.RemoveTagsFromCertificateRequest) (*api.Unit, error) {
	c, e := s.owned(tx, "RemoveTagsFromCertificate", value(in.CertificateArn))
	if e != nil {
		return nil, e
	}
	for _, t := range in.Tags {
		if v, ok := c.Tags[value(t.Key)]; ok && (t.Value == nil || v == value(t.Value)) {
			delete(c.Tags, value(t.Key))
		}
	}
	c.Version++
	return &api.Unit{}, tx.PutCertificate(c)
}
func (s *Service) listTags(tx Transaction, in *api.ListTagsForCertificateRequest) (*api.ListTagsForCertificateResponse, error) {
	c, e := s.owned(tx, "ListTagsForCertificate", value(in.CertificateArn))
	if e != nil {
		return nil, e
	}
	out := &api.ListTagsForCertificateResponse{Tags: api.TagList{}}
	keys := make([]string, 0, len(c.Tags))
	for k := range c.Tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKey(k)), Value: new(api.TagValue(c.Tags[k]))})
	}
	return out, nil
}
