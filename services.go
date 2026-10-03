package stackd

import (
	"fmt"

	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/gateway"
)

func modeledService(name string, provider gateway.Provider, decode func(string, awsapi.Request) (awsapi.DecodedRequest, error)) (gateway.Service, error) {
	model, ok := awscatalog.LookupService(name)
	if !ok {
		return gateway.Service{}, fmt.Errorf("missing generated AWS model for %s", name)
	}
	var protocol gateway.Protocol
	switch model.Protocol {
	case awscatalog.AWSQuery:
		protocol = gateway.Query
	case awscatalog.EC2Query:
		protocol = gateway.EC2Query
	case awscatalog.AWSJSON11:
		protocol = gateway.JSON11
	case awscatalog.AWSJSON10:
		protocol = gateway.JSON10
	case awscatalog.RestJSON:
		protocol = gateway.RestJSON
	case awscatalog.RestXML:
		protocol = gateway.RestXML
	case awscatalog.RPCV2CBOR:
		protocol = gateway.RPCV2CBOR
	default:
		return gateway.Service{}, fmt.Errorf("unsupported wire protocol for %s: %s", name, model.Protocol)
	}
	return gateway.Service{Name: name, SigningName: model.SigningName, Protocol: protocol, QueryVersion: model.Version, Namespace: model.XMLNamespace, TargetPrefix: model.TargetPrefix, Provider: provider, Model: &model, Decode: decode}, nil
}
