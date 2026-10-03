package codebuild

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type buildspec struct {
	Version string `yaml:"version"`
	RunAs   string `yaml:"run-as"`
	Env     struct {
		Shell               string            `yaml:"shell"`
		Variables           map[string]string `yaml:"variables"`
		Secrets             map[string]string `yaml:"secrets-manager"`
		Parameters          map[string]string `yaml:"parameter-store"`
		Exported            []string          `yaml:"exported-variables"`
		GitCredentialHelper string            `yaml:"git-credential-helper"`
	} `yaml:"env"`
	Phases    map[string]phaseSpec `yaml:"phases"`
	Artifacts artifactSpec         `yaml:"artifacts"`
	Cache     struct {
		Paths        []string `yaml:"paths"`
		Key          string   `yaml:"key"`
		FallbackKeys []string `yaml:"fallback-keys"`
		Action       string   `yaml:"action"`
	} `yaml:"cache"`
	Reports map[string]yaml.Node `yaml:"reports"`
	Batch   yaml.Node            `yaml:"batch"`
	Proxy   yaml.Node            `yaml:"proxy"`
}
type phaseSpec struct {
	Commands        []string          `yaml:"commands"`
	Finally         []string          `yaml:"finally"`
	RunAs           string            `yaml:"run-as"`
	OnFailure       string            `yaml:"on-failure"`
	RuntimeVersions map[string]string `yaml:"runtime-versions"`
	RuntimeCommands []string          `yaml:"-"`
}
type artifactSpec struct {
	Files          []string                `yaml:"files"`
	BaseDirectory  string                  `yaml:"base-directory"`
	DiscardPaths   bool                    `yaml:"discard-paths"`
	ExcludePaths   []string                `yaml:"exclude-paths"`
	EnableSymlinks bool                    `yaml:"enable-symlinks"`
	Name           string                  `yaml:"name"`
	S3Prefix       string                  `yaml:"s3-prefix"`
	Secondary      map[string]artifactSpec `yaml:"secondary-artifacts"`
}
type retainedSpec struct {
	Artifacts            artifactSpec
	CachePaths           []string
	Exported             []string
	SensitiveEnvironment []string
}

var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// CodePipeline artifact names allow hyphens; project source identifiers allow
// alphanumerics/underscores up to 127 characters. Admission owns each contract.
var sourceIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,127}$`)
var phaseNames = []string{"install", "pre_build", "build", "post_build"}

func parseBuildspec(spec Specification, source []File) (buildspec, error) {
	text := spec.Buildspec
	inline := strings.Contains(text, "\n")
	if !inline && text != "" {
		// YAML flow mappings (including JSON) are inline buildspecs too.
		// Inspect the document kind rather than guessing from a version prefix.
		var document yaml.Node
		if err := yaml.NewDecoder(strings.NewReader(text)).Decode(&document); err == nil {
			inline = len(document.Content) == 1 && document.Content[0].Kind == yaml.MappingNode
		}
	}
	if !inline {
		filename := text
		if filename == "" {
			filename = "buildspec.yml"
		}
		clean, err := workspacePath(filename)
		if err != nil {
			return buildspec{}, err
		}
		found := false
		for _, file := range source {
			if file.Path == clean {
				text = string(file.Body)
				found = true
				break
			}
		}
		if !found {
			return buildspec{}, fmt.Errorf("buildspec %q not found in source", filename)
		}
	}
	var result buildspec
	decoder := yaml.NewDecoder(strings.NewReader(text))
	decoder.KnownFields(true)
	if err := decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("invalid buildspec: %w", err)
	}
	if result.Version != "0.1" && result.Version != "0.2" {
		return result, fmt.Errorf("unsupported buildspec version %q", result.Version)
	}
	// TODO: Comeback: reports/batch need service-owned publication/orchestration;
	// proxy settings need an explicit runtime egress proxy integration.
	if len(result.Reports) != 0 || result.Batch.Kind != 0 || result.Proxy.Kind != 0 {
		return result, fmt.Errorf("reports, batch and proxy buildspec settings are not supported by this runtime")
	}
	if result.Env.GitCredentialHelper != "" && result.Env.GitCredentialHelper != "no" {
		return result, fmt.Errorf("persistent Git credential helpers are not supported")
	}
	if result.Env.Shell != "" && result.Env.Shell != "bash" && result.Env.Shell != "/bin/sh" {
		return result, fmt.Errorf("unsupported build shell %q", result.Env.Shell)
	}
	for name, phase := range result.Phases {
		known := false
		for _, valid := range phaseNames {
			if name == valid {
				known = true
				break
			}
		}
		if !known {
			return result, fmt.Errorf("unknown build phase %q", name)
		}
		if len(phase.RuntimeVersions) != 0 && name != "install" {
			return result, fmt.Errorf("runtime-versions is only supported in install")
		}
		if _, _, err := phaseRetry(phase.OnFailure); err != nil {
			return result, fmt.Errorf("phase %s: %w", name, err)
		}
	}
	for key := range result.Env.Variables {
		if !environmentName.MatchString(key) || strings.HasPrefix(key, "CODEBUILD_") {
			return result, fmt.Errorf("invalid buildspec environment variable %q", key)
		}
	}
	for key := range result.Env.Secrets {
		if !environmentName.MatchString(key) || strings.HasPrefix(key, "CODEBUILD_") {
			return result, fmt.Errorf("invalid secret environment variable %q", key)
		}
	}
	for key := range result.Env.Parameters {
		if !environmentName.MatchString(key) || strings.HasPrefix(key, "CODEBUILD_") {
			return result, fmt.Errorf("invalid parameter environment variable %q", key)
		}
	}
	for _, key := range result.Env.Exported {
		if !environmentName.MatchString(key) || strings.HasPrefix(key, "AWS_") || result.Env.Secrets[key] != "" || result.Env.Parameters[key] != "" {
			return result, fmt.Errorf("environment variable %q cannot be exported", key)
		}
	}
	if result.Cache.Key != "" || len(result.Cache.FallbackKeys) != 0 || result.Cache.Action != "" {
		return result, fmt.Errorf("dynamic cache keys and cache actions are not supported")
	}
	for _, pattern := range result.Cache.Paths {
		if err := validatePattern(pattern); err != nil {
			return result, err
		}
	}
	if err := validateArtifact(result.Artifacts); err != nil {
		return result, err
	}
	return result, nil
}

func validatePattern(pattern string) error {
	pattern = strings.TrimPrefix(pattern, "/codebuild/src/")
	if _, err := workspacePath(pattern); err != nil {
		return err
	}
	return nil
}
func validateArtifact(spec artifactSpec) error {
	if spec.EnableSymlinks {
		return fmt.Errorf("artifact symlinks are not supported")
	}
	if spec.BaseDirectory != "" && spec.BaseDirectory != "." {
		if err := validatePattern(spec.BaseDirectory); err != nil {
			return err
		}
	}
	for _, pattern := range append(append([]string{}, spec.Files...), spec.ExcludePaths...) {
		if err := validatePattern(pattern); err != nil {
			return err
		}
	}
	for _, secondary := range spec.Secondary {
		if err := validateArtifact(secondary); err != nil {
			return err
		}
	}
	return nil
}

func buildEnvironment(ctx context.Context, spec Specification, parsed buildspec) ([]string, error) {
	values := make(map[string]string, len(spec.Environment)+len(parsed.Env.Variables)+len(parsed.Env.Secrets)+len(parsed.Env.Parameters)+4)
	for key, value := range parsed.Env.Variables {
		values[key] = value
	}
	overrides := make(map[string]bool, len(spec.Environment))
	for _, entry := range spec.Environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || !environmentName.MatchString(key) || strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("invalid build environment variable")
		}
		values[key] = value
		overrides[key] = true
	}
	references := make([]string, 0, len(parsed.Env.Parameters))
	for key, reference := range parsed.Env.Parameters {
		if !overrides[key] {
			references = append(references, reference)
		}
	}
	if len(references) != 0 {
		if spec.ResolveParameters == nil {
			return nil, fmt.Errorf("buildspec Parameter Store resolver is unavailable")
		}
		sort.Strings(references)
		parameters, err := spec.ResolveParameters(ctx, references)
		if err != nil {
			return nil, fmt.Errorf("resolving buildspec parameters: %w", err)
		}
		for key, reference := range parsed.Env.Parameters {
			if overrides[key] {
				continue
			}
			value, found := parameters[reference]
			if !found {
				return nil, fmt.Errorf("SSM parameter for environment variable %q was not returned", key)
			}
			if strings.ContainsRune(value, 0) {
				return nil, fmt.Errorf("SSM parameter for environment variable %q contains NUL", key)
			}
			values[key] = value
		}
	}
	for key, reference := range parsed.Env.Secrets {
		if overrides[key] {
			continue
		}
		if spec.ResolveSecret == nil {
			return nil, fmt.Errorf("buildspec Secrets Manager resolver is unavailable")
		}
		value, err := spec.ResolveSecret(ctx, reference)
		if err != nil {
			return nil, fmt.Errorf("resolving buildspec secret %s: %w", key, err)
		}
		if strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("secret %s contains NUL", key)
		}
		values[key] = value
	}
	values["CODEBUILD_SRC_DIR"] = "/codebuild/src"
	for _, input := range spec.SecondarySources {
		values["CODEBUILD_SRC_DIR_"+input.Identifier] = "/codebuild/secondary/" + input.Identifier
	}
	values["CODEBUILD_BUILD_SUCCEEDING"] = "1"
	values["AWS_EC2_METADATA_DISABLED"] = "true"
	values["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
	values["AWS_CONFIG_FILE"] = "/dev/null"
	values["HOME"] = "/codebuild/home"
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment, nil
}
func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func controlFiles(parsed buildspec, sensitive []string) ([]File, error) {
	names := append([]string(nil), sensitive...)
	for name := range parsed.Env.Secrets {
		names = append(names, name)
	}
	for name := range parsed.Env.Parameters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range parsed.Env.Exported {
		index := sort.SearchStrings(names, name)
		if index < len(names) && names[index] == name {
			return nil, fmt.Errorf("secret environment variable %q cannot be exported", name)
		}
	}
	retained, err := json.Marshal(retainedSpec{Artifacts: parsed.Artifacts, CachePaths: parsed.Cache.Paths, Exported: parsed.Env.Exported, SensitiveEnvironment: names})
	if err != nil {
		return nil, err
	}
	files := []File{{Path: "codebuild/control/spec.json", Body: retained}}
	var runner strings.Builder
	runner.WriteString("#!/bin/sh\nset -e\numask 077\nmkdir -p /codebuild/state /codebuild/home /codebuild/src /codebuild/pipes\nmkfifo /codebuild/pipes/commands /codebuild/pipes/results\nexec 3<>/codebuild/pipes/commands 4<>/codebuild/pipes/results\ncd /codebuild/src\n_cb_exit=0\n_cb_phase=''\n_cb_child=''\n_cb_user=''\n")
	fmt.Fprintf(&runner, "_cb_shell=%s\n_cb_version=%s\n", shellQuote(buildShell(parsed)), shellQuote(parsed.Version))
	runner.WriteString(shellFunctions)
	runner.WriteString("trap '_cb_complete $?' EXIT\ntrap '_cb_stop 143' TERM\ntrap '_cb_stop 130' INT\n")
	for _, name := range phaseNames {
		phase, exists := parsed.Phases[name]
		if !exists {
			continue
		}
		upper := strings.ToUpper(name)
		user := phase.RunAs
		if user == "" {
			user = parsed.RunAs
		}
		retries, pattern, err := phaseRetry(phase.OnFailure)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&runner, "_cb_begin %s %s\n_cb_phase_run %s %d %s\n_cb_end \"$_cb_code\"\n", upper, shellQuote(user), name, retries, shellQuote(pattern))
		if phase.OnFailure == "ABORT" || (phase.OnFailure != "CONTINUE" && name != "build" && name != "post_build") {
			runner.WriteString("if [ \"$_cb_code\" -ne 0 ]; then exit \"$_cb_exit\"; fi\n")
		}
		for _, block := range []struct {
			name     string
			commands []string
		}{{"commands", phase.Commands}, {"finally", phase.Finally}} {
			var script strings.Builder
			if block.name == "commands" {
				// Image selectors configure the worker environment even when
				// version 0.1 isolates each subsequent customer command.
				for _, command := range phase.RuntimeCommands {
					fmt.Fprintf(&script, "eval %s\n", shellQuote(command))
				}
			}
			for _, command := range block.commands {
				// Print the command, not an expanded shell trace containing role secrets.
				fmt.Fprintf(&script, "printf '%%s\\n' %s\n", shellQuote("[Container] Running command "+command))
				if pattern != "" {
					script.WriteString("_cb_capture\n")
				}
				if parsed.Version == "0.1" {
					fmt.Fprintf(&script, "%s -c %s\n", shellQuote(buildShell(parsed)), shellQuote(command))
				} else {
					fmt.Fprintf(&script, "eval %s\n", shellQuote(command))
				}
				script.WriteString("_cb_command_code=$?\n")
				if pattern != "" {
					script.WriteString("_cb_capture_end\n")
				}
				script.WriteString("if [ \"$_cb_command_code\" -ne 0 ]; then exit \"$_cb_command_code\"; fi\n")
			}
			if script.Len() == 0 {
				script.WriteString(":\n")
			}
			files = append(files, File{Path: "codebuild/control/" + name + "." + block.name, Body: []byte(script.String())})
		}
	}
	runner.WriteString("exit \"$_cb_exit\"\n")
	var exported strings.Builder
	for _, key := range parsed.Env.Exported {
		fmt.Fprintf(&exported, "printf '%%s\\000%%s\\000' %s \"${%s-}\"\n", shellQuote(key), key)
	}
	if exported.Len() == 0 {
		exported.WriteString(":\n")
	}
	var artifactNames strings.Builder
	artifactNames.WriteString("{\n")
	selectors := []string{"artifacts"}
	for key := range parsed.Artifacts.Secondary {
		selectors = append(selectors, "artifacts:"+key)
	}
	sort.Strings(selectors)
	for _, selector := range selectors {
		artifact := parsed.Artifacts
		if selector != "artifacts" {
			artifact = parsed.Artifacts.Secondary[strings.TrimPrefix(selector, "artifacts:")]
		}
		if artifact.Name != "" {
			fmt.Fprintf(&artifactNames, "eval %s\n", shellQuote("printf '%s\\000%s\\000' "+shellQuote(selector)+" \""+artifact.Name+"\""))
		}
	}
	artifactNames.WriteString(":\n} > /codebuild/state/artifact_names.tmp\nmv /codebuild/state/artifact_names.tmp /codebuild/state/artifact_names\n")
	files = append(files,
		File{Path: "codebuild/control/export.sh", Body: []byte(exported.String())},
		File{Path: "codebuild/control/artifact-names.commands", Body: []byte(artifactNames.String())},
		File{Path: "codebuild/control/block.sh", Body: []byte(blockRunner)},
		File{Path: "codebuild/control/run.sh", Body: []byte(runner.String()), Mode: 0700})
	return files, nil
}

func buildShell(parsed buildspec) string {
	if parsed.Env.Shell == "bash" {
		return "/bin/bash"
	}
	return "/bin/sh"
}

func phaseRetry(policy string) (int, string, error) {
	switch policy {
	case "", "ABORT", "CONTINUE":
		return 0, "", nil
	case "RETRY":
		return 3, "", nil
	}
	if !strings.HasPrefix(policy, "RETRY-") {
		return 0, "", fmt.Errorf("invalid on-failure setting %q", policy)
	}
	value := strings.TrimPrefix(policy, "RETRY-")
	count, pattern := 3, value
	first, rest, split := strings.Cut(value, "-")
	if numeric, err := strconv.Atoi(first); err == nil {
		if numeric < 0 || numeric > 100 {
			return 0, "", fmt.Errorf("on-failure retry count must be between 0 and 100")
		}
		count, pattern = numeric, rest
		if !split {
			return count, "", nil
		}
	}
	if pattern == "" {
		return 0, "", fmt.Errorf("on-failure retry pattern is empty")
	}
	// The runtime uses native grep -E, so reject a different regex dialect
	// rather than accept it and silently match different error output.
	if _, err := regexp.CompilePOSIX(pattern); err != nil {
		return 0, "", fmt.Errorf("on-failure requires a POSIX extended regular expression: %w", err)
	}
	return count, pattern, nil
}

// The supervisor survives customer exit/errexit. A persistent native shell
// retains all shell state on successful 0.2 blocks; only a failed/exited shell
// restarts from its exported environment and cwd for finally/POST_BUILD.
// Version 0.1 gives each command its own shell. State files rename atomically.
const shellFunctions = `_cb_begin() {
 _cb_phase=$1
 if [ "$_cb_user" != "$2" ]; then _cb_shutdown; fi
 _cb_user=$2
 _cb_start=$(date +%s)
 printf '%s\tRUNNING\t%s\t0\t0\n' "$_cb_phase" "$_cb_start" > /codebuild/state/phase.tmp
 mv /codebuild/state/phase.tmp "/codebuild/state/$_cb_phase"
 printf '[Container] Phase %s started\n' "$_cb_phase"
 if [ -n "$_cb_user" ]; then
  chmod a+rx /codebuild /codebuild/control
  chmod a+r /codebuild/control/*.sh /codebuild/control/*.commands /codebuild/control/*.finally
  chown -R "$_cb_user" /codebuild/src /codebuild/state /codebuild/home /codebuild/pipes
  if [ -d /codebuild/secondary ]; then chown -R "$_cb_user" /codebuild/secondary; fi
 fi
 set +e
}
_cb_exec_worker() {
 if [ -f /codebuild/state/environment ]; then
  set -- env -i "$_cb_shell" /codebuild/control/block.sh "$_cb_version"
 else
  set -- "$_cb_shell" /codebuild/control/block.sh "$_cb_version"
 fi
 if [ -n "$_cb_user" ]; then
  # All positional values here are generated paths, version/status literals.
  exec su -p -s "$_cb_shell" -c "$*" "$_cb_user"
 fi
 exec "$@"
}
_cb_reply() {
 IFS=' ' read -r _cb_reply_kind _cb_run_code <&4
 if [ "$_cb_reply_kind" = exit ]; then
  wait "$_cb_child"
  _cb_child=''
 fi
 return "$_cb_run_code"
}
_cb_run() {
 if [ -z "$_cb_child" ]; then
  (
   _cb_exec_worker &
   _cb_process=$!
   trap 'kill -TERM "$_cb_process" 2>/dev/null' TERM INT
   wait "$_cb_process"
   _cb_worker_exit=$?
   printf 'exit %s\n' "$_cb_worker_exit" >&4
  ) &
  _cb_child=$!
 fi
 printf '%s %s\n' "$1" "$CODEBUILD_BUILD_SUCCEEDING" >&3
 _cb_reply
}
_cb_shutdown() {
 if [ -n "$_cb_child" ]; then
  printf '!stop 0\n' >&3
  _cb_reply
 fi
}
_cb_phase_run() {
 _cb_block=$1
 _cb_retries=$2
 _cb_pattern=$3
 _cb_before=$CODEBUILD_BUILD_SUCCEEDING
 _cb_attempt=0
 _cb_first_code=0
 while :; do
  CODEBUILD_BUILD_SUCCEEDING=$_cb_before
  _cb_run "$_cb_block.commands"
  _cb_code=$?
  if [ "$_cb_code" -ne 0 ]; then
   CODEBUILD_BUILD_SUCCEEDING=0
   if [ -n "$_cb_pattern" ]; then cp /codebuild/state/command.log /codebuild/state/phase-error.log; fi
  fi
  _cb_run "$_cb_block.finally"
  _cb_final_code=$?
  if [ "$_cb_code" -eq 0 ]; then
   _cb_code=$_cb_final_code
   if [ "$_cb_code" -ne 0 ] && [ -n "$_cb_pattern" ]; then cp /codebuild/state/command.log /codebuild/state/phase-error.log; fi
  fi
  if [ "$_cb_code" -eq 0 ]; then CODEBUILD_BUILD_SUCCEEDING=$_cb_before; break; fi
  if [ "$_cb_first_code" -eq 0 ]; then _cb_first_code=$_cb_code; fi
  if [ "$_cb_attempt" -ge "$_cb_retries" ]; then _cb_code=$_cb_first_code; break; fi
  if [ -n "$_cb_pattern" ] && ! LC_ALL=C grep -Eq -- "$_cb_pattern" /codebuild/state/phase-error.log; then _cb_code=$_cb_first_code; break; fi
  _cb_attempt=$((_cb_attempt + 1))
 done
 _cb_mark_failure "$_cb_code"
}
_cb_mark_failure() {
 if [ "$1" -ne 0 ]; then
  if [ "$_cb_exit" -eq 0 ]; then _cb_exit=$1; fi
  export CODEBUILD_BUILD_SUCCEEDING=0
 fi
}
_cb_end() {
 _cb_result=SUCCEEDED
 if [ "$1" -ne 0 ]; then _cb_result=FAILED; fi
 printf '%s\t%s\t%s\t%s\t%s\n' "$_cb_phase" "$_cb_result" "$_cb_start" "$(date +%s)" "$1" > /codebuild/state/phase.tmp
 mv /codebuild/state/phase.tmp "/codebuild/state/$_cb_phase"
 printf '[Container] Phase %s %s\n' "$_cb_phase" "$_cb_result"
 _cb_phase=''
}
_cb_complete() {
 _cb_complete_code=$1
 trap - EXIT
 set +e
 _cb_run artifact-names.commands
 _cb_names_code=$?
 _cb_shutdown
 if [ "$_cb_complete_code" -eq 0 ]; then _cb_complete_code=$_cb_names_code; fi
 exit "$_cb_complete_code"
}
_cb_stop() {
 trap - EXIT TERM INT
 if [ -n "$_cb_child" ]; then kill -TERM "$_cb_child" 2>/dev/null; fi
 exit "$1"
}
`

const blockRunner = `#!/bin/sh
set -e
set -a
if [ -f /codebuild/state/environment ]; then
 . /codebuild/state/environment
 cd "$_CB_SAVED_DIRECTORY"
else
 cd /codebuild/src
fi
_cb_tee=''
_cb_capture() {
 rm -f /codebuild/pipes/output
 mkfifo /codebuild/pipes/output
 tee /codebuild/state/command.log < /codebuild/pipes/output &
 _cb_tee=$!
 exec 5>&1 6>&2
 exec > /codebuild/pipes/output 2>&1
}
_cb_capture_end() {
 if [ -n "$_cb_tee" ]; then
  exec 1>&5 2>&6 5>&- 6>&-
  wait "$_cb_tee"
  _cb_tee=''
 fi
}
_cb_save() {
 _cb_saved_exit=$?
 trap - EXIT TERM INT
 set +e
 _cb_capture_end
 _CB_SAVED_DIRECTORY=$PWD
 export -p > /codebuild/state/environment.tmp
 mv /codebuild/state/environment.tmp /codebuild/state/environment
 . /codebuild/control/export.sh > /codebuild/state/exported.tmp
 mv /codebuild/state/exported.tmp /codebuild/state/exported
 exit "$_cb_saved_exit"
}
trap _cb_save EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
while IFS=' ' read -r _cb_file CODEBUILD_BUILD_SUCCEEDING <&3; do
 if [ "$_cb_file" = '!stop' ]; then exit 0; fi
 . "/codebuild/control/$_cb_file"
 printf 'ok 0\n' >&4
done
`
