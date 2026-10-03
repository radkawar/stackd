package eks

import "context"

// CoreDNSVersion is the AWS add-on release; native images remain upstream builds.
const CoreDNSVersion = "v1.12.3-eksbuild.1"
const CoreDNSImage = "rancher/mirrored-coredns-coredns:1.12.3"

func CoreDNSImageForVersion(version string) (string, bool) {
	switch version {
	case CoreDNSVersion:
		return CoreDNSImage, true
	case "v1.12.1-eksbuild.2":
		return "rancher/mirrored-coredns-coredns:1.12.1", true
	}
	return "", false
}

const defaultCorefile = `.:53 {
    errors
    health
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
    }
    prometheus :9153
    forward . /etc/resolv.conf
    cache 30
    loop
    reload
    loadbalance
}
`

type AddonSpecification struct {
	ClusterID, ClusterName, Region, ID, Name, Version, PreviousVersion, Configuration, PreviousConfiguration, ResolveConflicts string
	Delete, Preserve, Observe, Rollout                                                                                         bool
}
type AddonObservation struct {
	Configuration string
	Mutated       bool
}
type AddonRuntime interface {
	ReconcileAddon(context.Context, AddonSpecification) (AddonObservation, error)
}
type AddonError struct{ Code, Message string }

func (e *AddonError) Error() string { return e.Message }

// AddonPending records a real Kubernetes rollout still awaiting readiness.
type AddonPending struct{ Message string }

func (e *AddonPending) Error() string { return e.Message }
