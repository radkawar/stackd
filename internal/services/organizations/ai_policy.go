package organizations

import "fmt"

func aiOptOutPolicy(n *managementNode) error {
	if !managementObject(n) || len(n.children) != 1 || n.children["services"] == nil {
		return fmt.Errorf("AI opt-out policies require a services object")
	}
	services := n.children["services"]
	if !managementObject(services) {
		return fmt.Errorf("AI opt-out services must be objects")
	}
	for name, service := range services.children {
		if !aiOptOutServices[name] || !managementObject(service) {
			return fmt.Errorf("invalid AI opt-out service %q", name)
		}
		for field, setting := range service.children {
			if field != "opt_out_policy" || len(setting.children) != 0 || setting.append != nil || setting.remove != nil {
				return fmt.Errorf("invalid AI opt-out setting")
			}
			if setting.assigned {
				value, ok := setting.assign.(string)
				if !ok || value != "optIn" && value != "optOut" {
					return fmt.Errorf("AI opt-out values must be optIn or optOut")
				}
			}
		}
	}
	return nil
}
