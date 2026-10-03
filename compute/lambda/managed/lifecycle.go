package managed

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

func (s *Server) retainDeployment(d Deployment) (string, error) {
	directory := filepath.Join(s.config.StateDirectory, d.ID)
	raw, err := os.ReadFile(filepath.Join(directory, "deployment.json"))
	if err == nil {
		var current retainedDeployment
		if err = json.Unmarshal(raw, &current); err != nil {
			return "", err
		}
		if current.ProviderARN != s.config.Identity.ProviderARN || current.Generation != s.config.Identity.Generation || current.Deployment.ID != d.ID || current.Deployment.Revision != d.Revision || current.Deployment.Specification.FunctionARN != d.Specification.FunctionARN {
			return "", errors.New("retained managed deployment ownership differs")
		}
		return directory, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	staging, err := os.MkdirTemp(s.config.StateDirectory, ".environment-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	d.Specification.Logs = nil
	raw, err = json.Marshal(retainedDeployment{s.config.Identity.ProviderARN, s.config.Identity.Generation, d})
	if err != nil {
		return "", err
	}
	if err = atomicPrivateFile(filepath.Join(staging, "deployment.json"), raw); err != nil {
		return "", err
	}
	if err = os.Rename(staging, directory); err != nil {
		return "", err
	}
	return directory, nil
}

func (s *Server) removeRetained(ctx context.Context, id string) error {
	directory := filepath.Join(s.config.StateDirectory, id)
	if _, err := os.Stat(directory); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(directory, "deployment.json"))
	if err != nil {
		return err
	}
	var current retainedDeployment
	if err = json.Unmarshal(raw, &current); err != nil {
		return err
	}
	if current.ProviderARN != s.config.Identity.ProviderARN || current.Generation != s.config.Identity.Generation || current.Deployment.ID != id {
		return errors.New("refusing cleanup of another managed deployment incarnation")
	}
	if err = s.removeContainer(ctx, id); err != nil {
		return err
	}
	if err = unmountTemporary(ctx, directory); err != nil {
		return err
	}
	return os.RemoveAll(directory)
}
