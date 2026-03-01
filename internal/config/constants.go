package config

const (
	EnvHookMode   = "HOOK_MODE"
	ModeCreateRT  = "createruntime"
	ModeCreateCtr = "createcontainer"

	EnvCAFile          = "CAINJEKT_CA_FILE"
	EnvDynamicCARoot   = "CAINJEKT_DYNAMIC_CA_ROOT"
	EnvFailPolicy      = "CAINJEKT_FAIL_POLICY"
	EnvWrapperMode     = "CAINJEKT_WRAPPER_MODE"
	EnvHookContextFile = "CAINJEKT_HOOK_CONTEXT_FILE"

	AnnoEnabled = "cainjekt.io/enabled"

	AnnoProcessorsInclude = "cainjekt.io/processors.include"
	AnnoProcessorsExclude = "cainjekt.io/processors.exclude"

	FailPolicyOpen       = "fail-open"
	DefaultCAFile        = "/etc/cainjekt/ca-bundle.pem"
	DefaultDynamicCARoot = "/run/cainjekt/containers"
	DefaultMode          = "fs"
	WrapperPath          = "/cainjekt-entrypoint"
	HookContextFile      = "/etc/cainjekt/hook-context.json"

	DefaultHookTimeoutSec = 2
)
