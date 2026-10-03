// Package gateway routes AWS requests to explicitly registered service providers.
package gateway

import (
	"fmt"
	"net/http"
	"slices"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
)

type Protocol string

const (
	Query     Protocol = "query"
	EC2Query  Protocol = "ec2Query"
	JSON10    Protocol = "json1.0"
	JSON11    Protocol = "json1.1"
	RestJSON  Protocol = "restJson1"
	RestXML   Protocol = "restXml"
	RPCV2CBOR Protocol = "rpcv2Cbor"
)

// Provider describes behavior independently of how the gateway dispatches it.
type Provider interface {
	http.Handler
	Operations() []string
}

// privateOperationProvider owns native agent APIs absent from public SDK models.
// Routing occurs after the gateway's signature, region and body-bound checks;
// the provider supplies its generated private decoder and current authorization.
type privateOperationProvider interface {
	PrivateOperation(*http.Request) (string, bool)
	ServePrivateOperation(http.ResponseWriter, *http.Request)
}

type Service struct {
	Name         string
	SigningName  string
	Protocol     Protocol
	QueryVersion string
	Namespace    string
	TargetPrefix string
	Provider     Provider
	Model        *awscatalog.Service
	Decode       func(string, awsapi.Request) (awsapi.DecodedRequest, error)
}

// Registry is constructed before serving requests. New makes an immutable copy
// so extensions cannot race with in-flight routing or change advertised support.
type Registry struct {
	services []Service
}

func (r *Registry) Register(service Service) error {
	if service.Name == "" || service.SigningName == "" || service.Provider == nil {
		return fmt.Errorf("service name, signing name and provider are required")
	}
	switch service.Protocol {
	case Query, EC2Query:
		if service.QueryVersion == "" || service.Namespace == "" {
			return fmt.Errorf("query service %s needs a version and namespace", service.Name)
		}
	case JSON10, JSON11:
		if service.TargetPrefix == "" {
			return fmt.Errorf("JSON service %s needs a target prefix", service.Name)
		}
	case RestJSON, RestXML, RPCV2CBOR:
		if service.Model == nil || service.Decode == nil {
			return fmt.Errorf("service %s requires a generated model and decoder for %s", service.Name, service.Protocol)
		}
	default:
		return fmt.Errorf("unsupported protocol %q", service.Protocol)
	}
	for _, existing := range r.services {
		// DocumentDB shares the RDS Query API, including the target/ARN namespace.
		// Its model is registered for commands and capabilities; the RDS provider
		// composes public requests using engine/resource ownership and union reads.
		sharedRDS := existing.SigningName == "rds" && service.SigningName == "rds" &&
			existing.Protocol == Query && service.Protocol == Query &&
			existing.QueryVersion == service.QueryVersion && existing.Namespace == service.Namespace &&
			(existing.Name == "rds" && service.Name == "docdb" || existing.Name == "docdb" && service.Name == "rds")
		// AWS JSON services can share a SigV4 signing name: the generated
		// X-Amz-Target prefix distinguishes their protocol frontends. REST JSON
		// services use generated HTTP routes; S3 uses its host/header selector.
		// SES shares a signer across classic Query and versioned REST routes.
		ambiguousSigner := existing.SigningName == service.SigningName &&
			((existing.Protocol != JSON10 && existing.Protocol != JSON11) ||
				(service.Protocol != JSON10 && service.Protocol != JSON11)) &&
			!(existing.SigningName == "ses" &&
				(existing.Name == "ses" && existing.Protocol == Query && service.Name == "sesv2" && service.Protocol == RestJSON ||
					existing.Name == "sesv2" && existing.Protocol == RestJSON && service.Name == "ses" && service.Protocol == Query)) &&
			!(existing.SigningName == "s3" && existing.Protocol == RestXML && service.Protocol == RestXML &&
				(existing.Name == "s3" && service.Name == "s3control" || existing.Name == "s3control" && service.Name == "s3")) &&
			!(existing.SigningName == "apigateway" && existing.Protocol == RestJSON && service.Protocol == RestJSON &&
				(existing.Name == "apigateway" && service.Name == "apigatewayv2" || existing.Name == "apigatewayv2" && service.Name == "apigateway")) &&
			!(existing.SigningName == "appconfig" && existing.Protocol == RestJSON && service.Protocol == RestJSON &&
				(existing.Name == "appconfig" && service.Name == "appconfigdata" || existing.Name == "appconfigdata" && service.Name == "appconfig")) &&
			!(existing.SigningName == "es" && existing.Protocol == RestJSON && service.Protocol == RestJSON &&
				(existing.Name == "es" && service.Name == "opensearch" || existing.Name == "opensearch" && service.Name == "es"))
		if existing.Name == service.Name || !sharedRDS && (ambiguousSigner || (service.TargetPrefix != "" && existing.TargetPrefix == service.TargetPrefix)) {
			return fmt.Errorf("service %q has a conflicting registration", service.Name)
		}
	}
	operations := service.Provider.Operations()
	if len(operations) == 0 {
		return fmt.Errorf("service %q has no implemented operations", service.Name)
	}
	seen := make(map[string]bool, len(operations))
	for _, operation := range operations {
		if operation == "" || seen[operation] {
			return fmt.Errorf("service %q has invalid or duplicate operations", service.Name)
		}
		seen[operation] = true
		if service.Model != nil {
			if _, ok := service.Model.Operation(operation); !ok {
				return fmt.Errorf("service %q operation %q is absent from the generated AWS model", service.Name, operation)
			}
		}
	}
	r.services = append(r.services, service)
	return nil
}

type Capability struct {
	Name              string   `json:"name"`
	Protocol          Protocol `json:"protocol"`
	Operations        []string `json:"operations"`
	ModeledOperations int      `json:"modeled_operations,omitempty"`
	ModelRevision     string   `json:"model_revision,omitempty"`
}

func (g *Gateway) Capabilities() []Capability {
	capabilities := make([]Capability, 0, len(g.services))
	for _, service := range g.services {
		operations := slices.Clone(service.Provider.Operations())
		slices.Sort(operations)
		capability := Capability{Name: service.Name, Protocol: service.Protocol, Operations: operations}
		if service.Model != nil {
			capability.ModeledOperations = len(service.Model.Operations())
			capability.ModelRevision = service.Model.Source.Revision
		}
		capabilities = append(capabilities, capability)
	}
	slices.SortFunc(capabilities, func(a, b Capability) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return capabilities
}
