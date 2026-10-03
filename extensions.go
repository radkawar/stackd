package stackd

import (
	"fmt"
	"net/http"
	"slices"

	"stackd/extension"
	"stackd/internal/gateway"
)

type extensionProvider struct {
	http.Handler
	operations []string
}

func (p *extensionProvider) Operations() []string { return slices.Clone(p.operations) }

func registerExtension(registry *gateway.Registry, service extension.Service) error {
	if service.APIVersion != extension.APIVersion {
		return fmt.Errorf("extension %q: unsupported API version %d", service.Name, service.APIVersion)
	}
	if service.Handler == nil {
		return fmt.Errorf("extension %q: handler is required", service.Name)
	}
	return registry.Register(gateway.Service{
		Name: service.Name, SigningName: service.SigningName, Protocol: gateway.Protocol(service.Protocol),
		QueryVersion: service.QueryVersion, Namespace: service.Namespace, TargetPrefix: service.TargetPrefix,
		Provider: &extensionProvider{Handler: service.Handler, operations: slices.Clone(service.Operations)},
	})
}
