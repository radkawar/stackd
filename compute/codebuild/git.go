package codebuild

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Git is executed only inside the selected build image, with an explicit URL
// and an empty credential/configuration home. No host Git process or credential
// helper is consulted. Source credentials never enter the build container.
func (d *DockerExecutor) gitSource(ctx context.Context, spec Specification) ([]File, error) {
	git := spec.Git
	origin, err := url.Parse(git.URL)
	if err != nil || origin.Host == "" || origin.User != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Fragment != "" {
		return nil, fmt.Errorf("git source requires an explicit HTTP(S) URL without embedded credentials")
	}
	version := git.Version
	if version == "" {
		version = "HEAD"
	}
	if strings.HasPrefix(version, "-") || strings.ContainsAny(version, "\x00\r\n") {
		return nil, fmt.Errorf("invalid Git source version")
	}
	if git.Depth < 0 {
		return nil, fmt.Errorf("git clone depth must not be negative")
	}
	if strings.ContainsAny(git.Username+git.Password, "\x00\r\n") {
		return nil, fmt.Errorf("git source credentials contain unsupported line separators")
	}
	config, err := d.containerConfig(spec)
	if err != nil {
		return nil, err
	}
	config.Labels["stackd.codebuild.source"] = "true"
	config.Cmd = []string{"/codebuild/control/git.sh"}
	config.Env = []string{
		"HOME=/codebuild/home", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false",
		"GIT_SOURCE_URL=" + git.URL, "GIT_SOURCE_VERSION=" + version, "GIT_SOURCE_DEPTH=" + strconv.Itoa(git.Depth), "GIT_SOURCE_USERNAME=" + git.Username, "GIT_SOURCE_PASSWORD=" + git.Password,
		"GIT_SOURCE_SUBMODULES=" + strconv.FormatBool(git.FetchSubmodules),
		"GIT_SOURCE_ORIGIN=" + origin.Scheme + "://" + origin.Host,
	}
	name := d.name(spec.ARN) + "-source"
	state, err := d.nativeInspect(ctx, name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil {
		if state.Config.Labels[namespaceLabel] != d.config.Namespace || state.Config.Labels[arnLabel] != spec.ARN || state.Config.Labels["stackd.codebuild.source"] != "true" {
			return nil, fmt.Errorf("git source container ownership mismatch")
		}
		// An interrupted download is not a build execution. Replacing this exact
		// owned staging container cannot restart customer build commands.
		if err := d.client.RemoveContainer(ctx, state.ID); err != nil {
			return nil, err
		}
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := d.client.JSON(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), config, &created); err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = d.client.RemoveContainer(cleanup, created.ID)
	}()
	execution := &dockerExecution{executor: d, id: created.ID, arn: spec.ARN}
	archive, err := writeArchive([]File{
		{Path: "codebuild/control/git.sh", Body: []byte(gitScript), Mode: 0700},
		{Path: "codebuild/control/credential.sh", Body: []byte(gitCredentialScript), Mode: 0700},
	})
	if err != nil {
		return nil, err
	}
	if err := execution.upload(ctx, archive); err != nil {
		return nil, err
	}
	if err := d.client.JSON(ctx, "POST", execution.endpoint()+"/start", nil, nil); err != nil {
		return nil, err
	}
	var result struct {
		StatusCode int
		Error      *struct{ Message string }
	}
	if err := d.client.JSON(ctx, "POST", execution.endpoint()+"/wait?condition=not-running", nil, &result); err != nil {
		return nil, fmt.Errorf("retrieving Git source: %w", err)
	}
	if result.Error != nil {
		return nil, fmt.Errorf("retrieving Git source: %s", result.Error.Message)
	}
	if result.StatusCode != 0 {
		logs, _, _ := execution.Logs(ctx, 0)
		message := string(logs)
		for _, secret := range []string{git.Username, git.Password} {
			if secret != "" {
				message = strings.ReplaceAll(message, secret, "***")
			}
		}
		if len(message) > 4096 {
			message = message[:4096]
		}
		return nil, fmt.Errorf("git source exited with status %d: %s", result.StatusCode, message)
	}
	return execution.archive(ctx, "/codebuild/src")
}

const gitScript = `#!/bin/sh
set -eu
umask 077
mkdir -p /codebuild/src /codebuild/home
cd /codebuild/src
git() {
 command git -c credential.helper= -c credential.helper=/codebuild/control/credential.sh -c core.hooksPath=/dev/null -c protocol.file.allow=never -c protocol.ext.allow=never "$@"
}
command -v git >/dev/null || { printf '%s\n' 'The build image must contain Git for Git sources'; exit 127; }
git -c init.templateDir= init --quiet
if [ "$GIT_SOURCE_DEPTH" -gt 0 ]; then
 set -- --depth "$GIT_SOURCE_DEPTH"
else
 set --
fi
git fetch --quiet "$@" -- "$GIT_SOURCE_URL" "$GIT_SOURCE_VERSION"
# Relative submodule URLs resolve against the credential-free origin.
git remote add origin "$GIT_SOURCE_URL"
git checkout --quiet --detach FETCH_HEAD
if [ "$GIT_SOURCE_SUBMODULES" = true ]; then
 git submodule update --init --recursive "$@"
fi
`

// Credentials are scoped to the source authority. A repository can name
// arbitrary submodule hosts; those hosts must never receive its source secret.
const gitCredentialScript = `#!/bin/sh
[ "$1" = get ] || exit 0
protocol=''
host=''
while IFS='=' read -r key value; do
 case "$key" in
  protocol) protocol=$value ;;
  host) host=$value ;;
 esac
done
[ "$protocol://$host" = "$GIT_SOURCE_ORIGIN" ] || exit 0
printf 'username=%s\npassword=%s\n' "$GIT_SOURCE_USERNAME" "$GIT_SOURCE_PASSWORD"
`
