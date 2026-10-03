package integrations

import (
	"fmt"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/services/cloudformation"
)

func cfnLambdaMappingMQUpdate(mapping *api.EventSourceMappingConfiguration, p cloudformation.Properties) error {
	if len(mapping.Queues) == 0 {
		return nil
	}
	queues, _ := p["Queues"].([]any)
	if len(queues) != len(mapping.Queues) {
		return fmt.Errorf("parameter 'Queues' cannot be updated")
	}
	for i, queue := range mapping.Queues {
		if queues[i] != string(queue) {
			return fmt.Errorf("parameter 'Queues' cannot be updated")
		}
	}
	return nil
}
