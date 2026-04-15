// Package config defines environment variable names, annotation keys, and defaults.
package config

import (
	"os"
	"strings"
)

// Environment variables, annotations, and default values for cainjekt.
const (
	EnvHookMode   = "HOOK_MODE"
	ModeCreateRT  = "createruntime"
	ModeCreateCtr = "createcontainer"

	EnvCAFile            = "CAINJEKT_CA_FILE"
	EnvDynamicCARoot     = "CAINJEKT_DYNAMIC_CA_ROOT"
	EnvFailPolicy        = "CAINJEKT_FAIL_POLICY"
	EnvWrapperMode       = "CAINJEKT_WRAPPER_MODE"
	EnvHookContextFile   = "CAINJEKT_HOOK_CONTEXT_FILE"
	EnvPluginBinaryPath  = "CAINJEKT_PLUGIN_BINARY_PATH"
	EnvAnnotationPrefix  = "CAINJEKT_ANNOTATION_PREFIX"
	EnvLogLevel          = "CAINJEKT_LOG_LEVEL"
	EnvHookTimeoutSec    = "CAINJEKT_HOOK_TIMEOUT_SEC"
	EnvExcludeContainers = "CAINJEKT_EXCLUDE_CONTAINERS"

	DefaultAnnotationPrefix = "cainjekt.natron.io"

	FailPolicyOpen          = "fail-open"
	DefaultCAFile           = "/etc/cainjekt/ca-bundle.pem"
	DefaultDynamicCARoot    = "/run/cainjekt/containers"
	DefaultMode             = "fs"
	WrapperPath             = "/cainjekt-entrypoint"
	HookContextFile         = "/etc/cainjekt/hook-context.json"
	DefaultPluginBinaryPath = "/opt/cainjekt/bin/cainjekt"

	DefaultHookTimeoutSec = 2
)

// annotationPrefix is the resolved prefix, set once at init.
var annotationPrefix string

func init() {
	if v := strings.TrimSpace(os.Getenv(EnvAnnotationPrefix)); v != "" {
		annotationPrefix = strings.TrimSuffix(v, "/")
	} else {
		annotationPrefix = DefaultAnnotationPrefix
	}
}

// AnnoEnabled returns the annotation key for enabling injection.
func AnnoEnabled() string { return annotationPrefix + "/enabled" }

// AnnoProcessorsInclude returns the annotation key for processor include filter.
func AnnoProcessorsInclude() string { return annotationPrefix + "/processors.include" }

// AnnoProcessorsExclude returns the annotation key for processor exclude filter.
func AnnoProcessorsExclude() string { return annotationPrefix + "/processors.exclude" }

// AnnoExcludeContainers returns the annotation key for per-container opt-out.
func AnnoExcludeContainers() string { return annotationPrefix + "/exclude-containers" }

// AnnotationPrefix returns the configured annotation prefix.
func AnnotationPrefix() string { return annotationPrefix }
