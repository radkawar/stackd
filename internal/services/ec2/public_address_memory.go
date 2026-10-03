package ec2

import api "stackd/internal/awsapi/ec2"

func clonePublicAddress(v PublicAddressRecord) PublicAddressRecord {
	v.Data = api.CloneAddress(v.Data)
	return v
}

func (r memoryReader) PublicAddress(k ResourceKey) (PublicAddressRecord, error) {
	return getRecord(r.tx, r.s.publicAddresses, k, clonePublicAddress)
}
func (r memoryReader) PublicAddresses(scope Scope) ([]PublicAddressRecord, error) {
	return listRecords(r.tx, r.s.publicAddresses, scope, clonePublicAddress)
}
func (r memoryReader) PublicIPv4Reservations() ([]string, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(r.s.publicAddresses))
	for _, v := range r.s.publicAddresses {
		if ip := str(v.Data.PublicIp); ip != "" {
			out = append(out, ip)
		}
	}
	return out, nil
}
func (w memoryWriter) PutPublicAddress(v PublicAddressRecord) error {
	return putRecord(w.tx, w.s.publicAddresses, v.Key, v, clonePublicAddress)
}
func (w memoryWriter) DeletePublicAddress(k ResourceKey) error {
	return deleteRecord(w.tx, w.s.publicAddresses, k)
}
