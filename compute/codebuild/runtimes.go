package codebuild

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Runtime commands come from the selected image, not a second catalog of
// installed languages. AWS's image definitions install this manifest at
// /codebuild/image/config/runtimes.yml:
// https://github.com/aws/aws-codebuild-docker-images/blob/master/ubuntu/standard/7.0/runtimes.yml
func runtimeCommands(manifest []byte, requested map[string]string, environment []string) ([]string, error) {
	var config struct {
		Runtimes map[string]struct {
			Versions map[string]struct {
				Commands []string `yaml:"commands"`
			} `yaml:"versions"`
		} `yaml:"runtimes"`
	}
	if err := yaml.Unmarshal(manifest, &config); err != nil {
		return nil, fmt.Errorf("reading image runtime manifest: %w", err)
	}
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	names := make([]string, 0, len(requested))
	for name := range requested {
		names = append(names, name)
	}
	sort.Strings(names)
	var commands []string
	for _, name := range names {
		version := os.Expand(requested[name], func(key string) string { return values[key] })
		runtime, ok := config.Runtimes[name]
		if !ok {
			return nil, fmt.Errorf("runtime %q is not supplied by the selected image", name)
		}
		selection, ok := runtime.Versions[version]
		if !ok {
			// The image owns custom-version installation too. Do not silently
			// choose a different preinstalled version when no selector exists.
			selection, ok = runtime.Versions["default"]
			if !ok || version == "" || version == "latest" || strings.HasSuffix(version, ".x") {
				return nil, fmt.Errorf("runtime %s version %q is not supplied by the selected image", name, version)
			}
			commands = append(commands, "export VERSION="+shellQuote(version))
		}
		if len(selection.Commands) == 0 {
			return nil, fmt.Errorf("runtime %s version %q has no image selection commands", name, version)
		}
		commands = append(commands, selection.Commands...)
	}
	return commands, nil
}
