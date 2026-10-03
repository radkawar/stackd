package cloudformation

import api "stackd/internal/awsapi/cloudformation"

// STANDARD uses the existing owner stabilization and rollback machinery. EXPRESS
// must not advertise completion before resources are ready through this path.
func deploymentRollback(config *api.DeploymentConfig, explicit *api.DisableRollback) (bool, error) {
	if config == nil {
		return truth(explicit), nil
	}
	if mode := text(config.Mode); mode != "" && mode != "STANDARD" {
		return false, failure("NotImplementedException", "EXPRESS deployment stabilization is not implemented.", 501)
	}
	if config.DisableRollback != nil {
		if explicit != nil && truth(explicit) != truth(config.DisableRollback) {
			return false, invalid("DeploymentConfig.DisableRollback conflicts with DisableRollback")
		}
		return truth(config.DisableRollback), nil
	}
	return truth(explicit), nil
}
