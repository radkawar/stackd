package valkey

import "errors"

func (m manifest) validatePorts() error {
	seen := make(map[int32]bool, len(m.Nodes)*2)
	claim := func(port int32) error {
		if port < 1 || port > 65535 || seen[port] {
			return errors.New("native Valkey retained ports are invalid or duplicated")
		}
		seen[port] = true
		return nil
	}
	for _, node := range m.Nodes {
		if err := claim(node.Port); err != nil {
			return err
		}
		// Older non-cluster manifests also reserved a bus socket. Preserve
		// and validate it, but new non-cluster engines need no unused port.
		if m.ClusterMode || node.BusPort != 0 {
			if err := claim(node.BusPort); err != nil {
				return err
			}
		}
	}
	return nil
}
