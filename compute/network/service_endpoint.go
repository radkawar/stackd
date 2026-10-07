package network

// ServiceEndpoint is a typed projection of an available EC2 endpoint and its
// actual managed ENI. Gateway endpoints use their effective prefix-list route;
// they have no fabricated ENI. Policy documents remain with the EC2 owner and
// are evaluated against each authenticated service action and resource.
type ServiceEndpoint struct {
	ID, Service, Kind string
	PrivateDNS        bool
	Network           Specification
}
