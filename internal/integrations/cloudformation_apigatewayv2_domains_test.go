package integrations

import (
	"reflect"
	"stackd/internal/services/cloudformation"
	"testing"
)

func TestV2DomainProjectionUsesOfficialResourceProperties(t *testing.T) {
	output := map[string]any{
		"DomainName": "api.example.test", "DomainNameArn": "arn:aws:apigateway:us-east-1::/domainnames/api.example.test",
		"RoutingMode": "API_MAPPING_ONLY", "Tags": map[string]any{"purpose": "test"},
		"DomainNameConfigurations": []any{map[string]any{"CertificateArn": "certificate", "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2", "IpAddressType": "ipv4", "DomainNameStatus": "AVAILABLE", "ApiGatewayDomainName": "127.0.0.1:9443"}},
		"MutualTlsAuthentication":  map[string]any{"TruststoreUri": "s3://trust/pem", "TruststoreVersion": "one", "TruststoreWarnings": []any{}},
	}
	model := cfnV2DomainModel(output)
	if model["RegionalDomainName"] != "127.0.0.1:9443" {
		t.Fatalf("actual endpoint lost: %#v", model)
	}
	if _, ok := model["RegionalHostedZoneId"]; ok {
		t.Fatal("invented hosted-zone provenance")
	}
	configs := model["DomainNameConfigurations"].([]any)
	if _, ok := configs[0].(map[string]any)["ApiGatewayDomainName"]; ok {
		t.Fatal("wire-only configuration field leaked into CFN")
	}
	if _, ok := configs[0].(map[string]any)["DomainNameStatus"]; ok {
		t.Fatal("wire-only status field leaked into CFN")
	}
	result := cfnV2DomainResult(output)
	if result.Ref != "api.example.test" || result.PhysicalID != "api.example.test" {
		t.Fatalf("domain identifier: %#v", result)
	}
	mapping := cfnV2MappingResult(map[string]any{"ApiMappingId": "mapping"}, "api.example.test")
	if mapping.PhysicalID != "mapping|api.example.test" || mapping.Ref != "mapping" {
		t.Fatalf("mapping official primary identifier: %#v", mapping)
	}
	ids, err := cfnGatewayV2Identifier(cloudformation.ResourceRequest{PhysicalID: mapping.PhysicalID}, "ApiMappingId", "DomainName")
	if err != nil || !reflect.DeepEqual(ids, map[string]any{"ApiMappingId": "mapping", "DomainName": "api.example.test"}) {
		t.Fatalf("mapping roundtrip: %#v %v", ids, err)
	}
}

func TestV2DomainValidationRejectsUnconsumedAndReadOnlyFields(t *testing.T) {
	handler := cfnV2Domain{}
	for _, p := range []cloudformation.Properties{
		{"DomainName": "api.example.test", "RegionalHostedZoneId": "invented"},
		{"DomainName": "api.example.test", "RoutingMode": "ROUTING_RULE_ONLY"},
		{"DomainName": "api.example.test", "DomainNameConfigurations": []any{map[string]any{"CertificateArn": "certificate", "HostedZoneId": "invented"}}},
		{"DomainName": "api.example.test", "MutualTlsAuthentication": map[string]any{"TruststoreWarnings": []any{}}},
	} {
		if err := handler.Validate(p); err == nil {
			t.Fatalf("unsupported properties accepted: %#v", p)
		}
	}
	if err := handler.Validate(cloudformation.Properties{"DomainName": "api.example.test", "DomainNameConfigurations": []any{map[string]any{"CertificateArn": "certificate", "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}}, "MutualTlsAuthentication": map[string]any{"TruststoreUri": "s3://trust/pem", "TruststoreVersion": "one"}}); err != nil {
		t.Fatal(err)
	}
}
