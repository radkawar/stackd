package elbv2

import (
	"context"

	api "stackd/internal/awsapi/elbv2"
)

// Listener header mutation is not implemented. These fixed attributes describe
// the actual native baseline: generated ALB responses carry awselb/2.0, target
// responses retain their own Server header, and no custom security/CORS headers
// are injected. An unchanged baseline request does not promise a missing effect.
func nativeListenerAttributes() api.ListenerAttributes {
	keys := [...]string{
		"routing.http.response.access_control_allow_credentials.header_value",
		"routing.http.response.access_control_allow_headers.header_value",
		"routing.http.response.access_control_allow_methods.header_value",
		"routing.http.response.access_control_allow_origin.header_value",
		"routing.http.response.access_control_expose_headers.header_value",
		"routing.http.response.access_control_max_age.header_value",
		"routing.http.response.content_security_policy.header_value",
		"routing.http.response.server.enabled",
		"routing.http.response.strict_transport_security.header_value",
		"routing.http.response.x_content_type_options.header_value",
		"routing.http.response.x_frame_options.header_value",
	}
	out := make(api.ListenerAttributes, len(keys))
	for index, key := range keys {
		v := ""
		if key == "routing.http.response.server.enabled" {
			v = "true"
		}
		out[index] = api.ListenerAttribute{Key: new(api.ListenerAttributeKey(key)), Value: new(api.ListenerAttributeValue(v))}
	}
	return out
}

func (s *Service) describeListenerAttributes(ctx context.Context, tx Transaction, in *api.DescribeListenerAttributesInput) (*api.DescribeListenerAttributesOutput, error) {
	l, err := listener(tx, scopeFor(ctx), value(in.ListenerArn))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "DescribeListenerAttributes", value(in.ListenerArn), l.Tags, nil); err != nil {
		return nil, err
	}
	return &api.DescribeListenerAttributesOutput{Attributes: nativeListenerAttributes()}, nil
}

func (s *Service) modifyListenerAttributes(ctx context.Context, tx Transaction, in *api.ModifyListenerAttributesInput) (*api.ModifyListenerAttributesOutput, error) {
	l, err := listener(tx, scopeFor(ctx), value(in.ListenerArn))
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "ModifyListenerAttributes", value(in.ListenerArn), l.Tags, nil); err != nil {
		return nil, err
	}
	attributes := nativeListenerAttributes()
	for _, requested := range in.Attributes {
		matched := false
		for _, supported := range attributes {
			if value(requested.Key) != value(supported.Key) {
				continue
			}
			matched = true
			if value(requested.Value) != value(supported.Value) {
				return nil, unsupported("Custom listener response headers and Server header removal require native header mutation support")
			}
			break
		}
		if !matched {
			return nil, unsupported("The requested listener attribute is not implemented by the native application listener")
		}
	}
	return &api.ModifyListenerAttributesOutput{Attributes: attributes}, nil
}
