package managed

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"stackd/compute/docker"
)

const credentialGateway = "169.254.170.2"

func (s *Server) ensureNetwork(ctx context.Context) error {
	s.network = "stackd-lambda-" + s.config.Identity.Generation
	var current struct {
		ID     string
		Labels map[string]string
		IPAM   struct {
			Config []struct{ Subnet, Gateway string }
		}
	}
	err := s.engine.JSON(ctx, "GET", "/networks/"+s.network, nil, &current)
	var absent *docker.Error
	if errors.As(err, &absent) && absent.StatusCode == 404 {
		request := struct {
			Name, Driver string
			EnableIPv6   bool
			Labels       map[string]string
			Options      map[string]string
			IPAM         struct {
				Config []struct{ Subnet, Gateway string }
			}
		}{Name: s.network, Driver: "bridge", Labels: map[string]string{"stackd.lambda.capacity-provider": s.config.Identity.ProviderARN, "stackd.lambda.guest-generation": s.config.Identity.Generation}}
		request.IPAM.Config = []struct{ Subnet, Gateway string }{{"169.254.170.0/24", credentialGateway}}
		if err = s.engine.JSON(ctx, "POST", "/networks/create", request, nil); err != nil {
			return err
		}
		if err = s.engine.JSON(ctx, "GET", "/networks/"+s.network, nil, &current); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if current.Labels["stackd.lambda.capacity-provider"] != s.config.Identity.ProviderARN || current.Labels["stackd.lambda.guest-generation"] != s.config.Identity.Generation || len(current.IPAM.Config) != 1 || current.IPAM.Config[0].Gateway != credentialGateway || len(current.ID) < 12 {
		return errors.New("managed Docker network ownership or gateway differs")
	}
	bridge := "br-" + current.ID[:12]
	// Customer runtimes must never inherit the instance profile used by the SSM
	// agent. This is an actual guest-kernel forwarding rule, not an SDK hint.
	rule := []string{"DOCKER-USER", "-i", bridge, "-d", "169.254.169.254/32", "-j", "REJECT"}
	output, err := exec.CommandContext(ctx, "iptables", append([]string{"-w", "5", "-C"}, rule...)...).CombinedOutput()
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		return fmt.Errorf("checking managed IMDS isolation: %w: %s", err, strings.TrimSpace(string(output)))
	}
	output, err = exec.CommandContext(ctx, "iptables", append([]string{"-w", "5", "-I"}, rule...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("installing managed IMDS isolation: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
