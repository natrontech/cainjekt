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
	EnvBreadcrumbDir     = "CAINJEKT_BREADCRUMB_DIR"

	DefaultAnnotationPrefix = "cainjekt.natron.io"

	FailPolicyOpen          = "fail-open"
	DefaultCAFile           = "/etc/cainjekt/ca-bundle.pem"
	DefaultDynamicCARoot    = "/run/cainjekt/containers"
	DefaultMode             = "fs"
	WrapperPath             = "/cainjekt-entrypoint"
	HookContextFile         = "/etc/cainjekt/hook-context.json"
	DefaultPluginBinaryPath = "/opt/cainjekt/bin/cainjekt"

	DefaultHookTimeoutSec = 20

	BreadcrumbStarted  = "hook.started"
	BreadcrumbProgress = "hook.progress"
	BreadcrumbDone     = "hook.done"
)

// Trust environment variables set on the container spec at CreateContainer time.
// The wrapper sets the same variables on the entrypoint process, but processes
// started via exec (kubectl exec, and therefore every step of a GitHub Actions
// container job) are seeded from the spec and never see the wrapper's env.
const (
	EnvSSLCertFile      = "SSL_CERT_FILE"
	EnvRequestsCABundle = "REQUESTS_CA_BUNDLE"
	EnvCurlCABundle     = "CURL_CA_BUNDLE"
	EnvGitSSLCAInfo     = "GIT_SSL_CAINFO"
	EnvNodeExtraCACerts = "NODE_EXTRA_CA_CERTS"
)

// Per-container CA staging. The dynamic CA dir is staged on the host and
// bind-mounted read-only into the container at ContainerCADir, so the paths below
// are fixed and therefore usable in the OCI spec env, which is decided before the
// hook has detected the distro.
const (
	// ContainerCADir is deliberately not /etc/cainjekt: the hook writes
	// hook-context.json and status.json into the rootfs there, and a bind mount
	// would shadow them.
	ContainerCADir = "/etc/cainjekt-ca"

	DynamicCAFileName = "ca-bundle.pem"
	MergedCAFileName  = "ca-bundle-merged.pem"

	// ContainerOrgCA is the bare org CA — for additive consumers (NODE_EXTRA_CA_CERTS).
	ContainerOrgCA = ContainerCADir + "/" + DynamicCAFileName
	// ContainerMergedCA is system roots + org CA — for trust-replacing consumers
	// (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, ...), which would otherwise drop the
	// public roots and break all public TLS.
	ContainerMergedCA = ContainerCADir + "/" + MergedCAFileName
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
