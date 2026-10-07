package integrations

import (
	"maps"

	"stackd/internal/services/cloudformation"
)

// CloudFormationHandlers assembles the built-in native owner adapters. Both the
// controller and generated support inventory use this registry; presence does
// not establish behavioral completeness. MSK configurations require their real
// typed owner when used; registry inspection does not invoke owner operations.
func CloudFormationHandlers(commands StepFunctionsCommands, configurations CloudFormationMSKConfigurationOwner) map[string]cloudformation.ResourceHandler {
	handlers := CloudFormationMessagingHandlers(commands)
	for _, family := range []map[string]cloudformation.ResourceHandler{
		CloudFormationComputeHandlers(commands),
		CloudFormationBootstrapHandlers(commands),
		CloudFormationKMSHandlers(commands),
		CloudFormationStorageHandlers(commands),
		CloudFormationCognitoHandlers(commands),
		CloudFormationDataStreamHandlers(commands),
		CloudFormationEC2Handlers(commands),
		CloudFormationAPIGatewayHandlers(commands),
		CloudFormationLambdaAdditionalHandlers(commands),
		CloudFormationIAMAdditionalHandlers(commands),
		CloudFormationOrganizationIdentityHandlers(commands),
		CloudFormationComputeServiceHandlers(commands),
		CloudFormationRelationalHandlers(commands),
		CloudFormationEngineClusterHandlers(commands, configurations),
		CloudFormationWorkflowHandlers(commands),
		CloudFormationAnalyticsHandlers(commands),
		CloudFormationDeveloperHandlers(commands),
		CloudFormationObservabilityHandlers(commands),
		CloudFormationConfigSecurityHandlers(commands),
		CloudFormationApplicationHandlers(commands),
		CloudFormationTrustDNSHandlers(commands),
		CloudFormationWAFHandlers(commands),
		CloudFormationStackHandlers(commands),
	} {
		maps.Copy(handlers, family)
	}
	return handlers
}
