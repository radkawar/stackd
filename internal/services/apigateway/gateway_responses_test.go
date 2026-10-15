package apigateway

import "testing"

func TestSpecificGatewayResponseAdmissionUsesExistingProducers(t *testing.T) {
	for _, test := range []struct {
		kind   string
		status int
	}{
		{"MISSING_AUTHENTICATION_TOKEN", 403},
		{"INVALID_API_KEY", 403},
		{"ACCESS_DENIED", 403},
		{"UNAUTHORIZED", 401},
		{"QUOTA_EXCEEDED", 429},
		{"THROTTLED", 429},
		{"REQUEST_TOO_LARGE", 413},
		{"INTEGRATION_TIMEOUT", 504},
		{"INTEGRATION_FAILURE", 504},
		{"API_CONFIGURATION_ERROR", 500},
		{"AUTHORIZER_FAILURE", 500},
		{"WAF_FILTERED", 403},
	} {
		t.Run(test.kind, func(t *testing.T) {
			response, err := parseGatewayResponse(test.kind, "", nil, nil)
			if err != nil || response.StatusCode != test.status {
				t.Fatalf("response=%#v error=%v", response, err)
			}
		})
	}
	for _, kind := range []string{"BAD_REQUEST_BODY", "BAD_REQUEST_PARAMETERS", "RESOURCE_NOT_FOUND", "UNSUPPORTED_MEDIA_TYPE", "EXPIRED_TOKEN", "INVALID_SIGNATURE", "AUTHORIZER_CONFIGURATION_ERROR"} {
		if _, err := parseGatewayResponse(kind, "", nil, nil); err == nil {
			t.Fatalf("accepted response without a classified execution producer: %s", kind)
		}
	}
	for _, kind := range []string{"DEFAULT_4XX", "DEFAULT_5XX"} {
		response, err := parseGatewayResponse(kind, "", nil, nil)
		if err != nil || response.StatusCode != 0 {
			t.Fatalf("fallback lost original status: %#v %v", response, err)
		}
	}
}
