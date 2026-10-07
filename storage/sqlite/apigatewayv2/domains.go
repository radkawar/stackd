package apigatewayv2

import (
	domain "stackd/internal/services/apigatewayv2"
	"stackd/storage/sqlite/apigatewayv2/internal/sqlcgen"
)

func rowDomain(v sqlcgen.Apigatewayv2Domain) (domain.DomainRecord, error) {
	out := domain.DomainRecord{Key: domain.DomainKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, Owner: domain.ResourceOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken}, CertificateARN: v.CertificateArn, CertificateID: v.CertificateID, CertificateName: v.CertificateName, OwnershipCertificateARN: v.OwnershipCertificateArn, OwnershipCertificateID: v.OwnershipCertificateID, SecurityPolicy: v.SecurityPolicy, IPAddressType: v.IpAddressType, TruststoreURI: v.TruststoreUri, TruststoreVersion: v.TruststoreVersion, TruststorePEM: v.TruststorePem}
	e := decode(v.Tags, &out.Tags)
	return out, e
}
func (r reader) Domain(k domain.DomainKey) (domain.DomainRecord, error) {
	v, e := r.q.GetDomain(r.ctx, sqlcgen.GetDomainParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if e != nil {
		return domain.DomainRecord{}, missing(e)
	}
	return rowDomain(v)
}
func (r reader) DomainByHost(host string) (domain.DomainRecord, error) {
	v, e := r.q.GetDomainByHost(r.ctx, host)
	if e != nil {
		return domain.DomainRecord{}, missing(e)
	}
	return rowDomain(v)
}
func (r reader) Domains(k domain.Scope) ([]domain.DomainRecord, error) {
	rows, e := r.q.ListDomains(r.ctx, sqlcgen.ListDomainsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.DomainRecord, len(rows))
	for i, v := range rows {
		out[i], e = rowDomain(v)
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (w writer) PutDomain(v domain.DomainRecord) error {
	tags, e := encode(v.Tags)
	if e != nil {
		return e
	}
	pem := v.TruststorePEM
	if pem == nil {
		pem = []byte{}
	}
	return w.q.PutDomain(w.ctx, sqlcgen.PutDomainParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, Name: v.Key.Name, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token, CertificateArn: v.CertificateARN, CertificateID: v.CertificateID, CertificateName: v.CertificateName, OwnershipCertificateArn: v.OwnershipCertificateARN, OwnershipCertificateID: v.OwnershipCertificateID, SecurityPolicy: v.SecurityPolicy, IpAddressType: v.IPAddressType, TruststoreUri: v.TruststoreURI, TruststoreVersion: v.TruststoreVersion, TruststorePem: pem, Tags: tags})
}
func (w writer) DeleteDomain(k domain.DomainKey) error {
	return w.q.DeleteDomain(w.ctx, sqlcgen.DeleteDomainParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
}
func rowMapping(v sqlcgen.Apigatewayv2Mapping) domain.MappingRecord {
	return domain.MappingRecord{Key: domain.MappingKey{DomainKey: domain.DomainKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.DomainName}, ID: v.ID}, Owner: domain.ResourceOwner{StackID: v.OwnerStackID, LogicalID: v.OwnerLogicalID, Token: v.OwnerToken}, APIID: v.ApiID, Stage: v.Stage, Path: v.Path}
}
func (r reader) Mapping(k domain.MappingKey) (domain.MappingRecord, error) {
	v, e := r.q.GetMapping(r.ctx, sqlcgen.GetMappingParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, DomainName: k.Name, ID: k.ID})
	if e != nil {
		return domain.MappingRecord{}, missing(e)
	}
	return rowMapping(v), nil
}
func (r reader) Mappings(k domain.DomainKey) ([]domain.MappingRecord, error) {
	rows, e := r.q.ListMappings(r.ctx, sqlcgen.ListMappingsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, DomainName: k.Name})
	if e != nil {
		return nil, e
	}
	out := make([]domain.MappingRecord, len(rows))
	for i, v := range rows {
		out[i] = rowMapping(v)
	}
	return out, nil
}
func (w writer) PutMapping(v domain.MappingRecord) error {
	return w.q.PutMapping(w.ctx, sqlcgen.PutMappingParams{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, DomainName: v.Key.Name, ID: v.Key.ID, OwnerStackID: v.Owner.StackID, OwnerLogicalID: v.Owner.LogicalID, OwnerToken: v.Owner.Token, ApiID: v.APIID, Stage: v.Stage, Path: v.Path})
}
func (w writer) DeleteMapping(k domain.MappingKey) error {
	return w.q.DeleteMapping(w.ctx, sqlcgen.DeleteMappingParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, DomainName: k.Name, ID: k.ID})
}
