package resourcegroups

import api "stackd/internal/awsapi/resourcegroups"

const genericConfigurationType = "AWS::ResourceGroups::Generic"

func (s *Service) getGroupConfiguration(tx Transaction, in *api.GetGroupConfigurationInput) (*api.GetGroupConfigurationOutput, error) {
	id, err := identifier(value(in.Group), "")
	if err != nil {
		return nil, err
	}
	g, err := s.loadGroup(tx, id, "GetGroupConfiguration")
	if err != nil {
		return nil, err
	}
	if g.ManagedType == "" {
		return nil, failure("BadRequestException", "This operation does not support the target")
	}
	return &api.GetGroupConfigurationOutput{GroupConfiguration: groupConfiguration(g)}, nil
}

func (s *Service) putGroupConfiguration(tx Transaction, in *api.PutGroupConfigurationInput) (*api.PutGroupConfigurationOutput, error) {
	id, err := identifier(value(in.Group), "")
	if err != nil {
		return nil, err
	}
	g, err := s.loadGroup(tx, id, "PutGroupConfiguration")
	if err != nil {
		return nil, err
	}
	if g.ManagedType != "" {
		return nil, failure("ForbiddenException", "Access denied. This group is managed by AppRegistry.")
	}
	return nil, failure("BadRequestException", "This operation does not support the target")
}

// configurationError rejects native-invalid input before reporting the missing
// real owner for an otherwise admissible service-linked configuration.
// https://docs.aws.amazon.com/ARG/latest/userguide/about-slg-types.html
func configurationError(configuration api.GroupConfigurationList, query *api.ResourceQuery) error {
	if len(configuration) == 0 || len(configuration) > 2 {
		return failure("BadRequestException", "Configuration must contain one or two items.")
	}
	seen := make(map[string]bool, len(configuration))
	for _, item := range configuration {
		typ := value(item.Type)
		if seen[typ] {
			return failure("BadRequestException", "Configuration types must be unique.")
		}
		seen[typ] = true
		switch typ {
		case genericConfigurationType, "AWS::EC2::HostManagement":
		case "AWS::EC2::CapacityReservationPool", "AWS::NetworkFirewall::RuleGroup":
			if len(item.Parameters) != 0 {
				return failure("BadRequestException", "The specified configuration does not accept parameters.")
			}
		case "AWS::AppRegistry::Application", "AWS::CloudFormation::Stack":
			return failure("ForbiddenException", "Access denied. This group is managed by AppRegistry.")
		case "AWS::ResourceGroups::ApplicationGroup":
			return failure("BadRequestException", "Operation is not supported")
		default:
			return failure("BadRequestException", "One or more group configuration items are not supported: "+typ)
		}
	}
	if len(seen) == 1 && seen[genericConfigurationType] {
		// Native rejects standalone Generic, even with allowed-resource-types.
		// It is not an arbitrary manually populated resource group.
		return failure("BadRequestException", "One or more parameters are missing: resourceQuery, configuration")
	}
	if (seen["AWS::EC2::CapacityReservationPool"] || seen["AWS::EC2::HostManagement"]) && !seen[genericConfigurationType] {
		return failure("BadRequestException", "One or more configuration are missing: AWS::ResourceGroups::Generic")
	}
	for _, item := range configuration {
		if value(item.Type) == genericConfigurationType {
			if err := validateGenericConfiguration(item.Parameters); err != nil {
				return err
			}
		}
	}
	if seen["AWS::NetworkFirewall::RuleGroup"] {
		q, err := parseQuery(query)
		if err != nil {
			return err
		}
		if value(query.Type) != string(api.QueryTypeTAG_FILTERS_1_0) || len(q.ResourceTypeFilters) != 1 || q.ResourceTypeFilters[0] != "AWS::EC2::Instance" {
			return failure("BadRequestException", "Network Firewall groups require a tag query over AWS::EC2::Instance.")
		}
	} else if query != nil {
		return failure("BadRequestException", "A query cannot be combined with this group configuration.")
	}
	// TODO: Comeback: EC2 capacity-reservation ownership and instance placement
	// into reservation pools are unavailable.
	if seen["AWS::EC2::CapacityReservationPool"] {
		return failure("NotImplementedException", "Capacity reservation pools require an EC2 capacity reservation owner, which is not available.")
	}
	// TODO: Comeback: EC2 Dedicated Host allocation and License Manager
	// host-management effects require their real service owners.
	if seen["AWS::EC2::HostManagement"] {
		return failure("NotImplementedException", "Host management groups require EC2 Dedicated Host and License Manager owners, which are not available.")
	}
	// TODO: Comeback: Network Firewall rule-group ownership and actual
	// associated-resource rule updates are unavailable.
	return failure("NotImplementedException", "Network Firewall groups require a Network Firewall rule-group owner, which is not available.")
}

func validateGenericConfiguration(parameters api.GroupParameterList) error {
	seen := make(map[string]bool, len(parameters))
	for _, parameter := range parameters {
		name := value(parameter.Name)
		if seen[name] {
			return failure("BadRequestException", "Configuration parameter names must be unique.")
		}
		seen[name] = true
		switch name {
		case "allowed-resource-types":
			if len(parameter.Values) == 0 {
				return failure("BadRequestException", "allowed-resource-types must contain at least one resource type.")
			}
			for _, typ := range parameter.Values {
				if typ != "AWS::EC2::Host" && typ != "AWS::EC2::CapacityReservation" {
					return failure("BadRequestException", "The specified allowed-resource-types value is not supported.")
				}
			}
		case "deletion-protection":
			if len(parameter.Values) != 1 || parameter.Values[0] != "UNLESS_EMPTY" {
				return failure("BadRequestException", "deletion-protection must have the single value UNLESS_EMPTY.")
			}
		default:
			return failure("BadRequestException", "The specified generic configuration parameter is not supported.")
		}
	}
	return nil
}
