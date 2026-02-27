package config

const (
	EnvHookMode   = "HOOK_MODE"
	ModeCreateRT  = "createruntime"
	ModeCreateCtr = "createcontainer"

	EnvCAFile          = "CAINJEKT_CA_FILE"
	EnvFailPolicy      = "CAINJEKT_FAIL_POLICY"
	EnvWrapperMode     = "CAINJEKT_WRAPPER_MODE"
	EnvHookContextFile = "CAINJEKT_HOOK_CONTEXT_FILE"

	LabelEnabled = "cainjekt.io/enabled"
	AnnoDisable  = "cainjekt.io/disable"
	AnnoMode     = "cainjekt.io/mode"

	AnnoProcessorsInclude = "cainjekt.io/processors.include"
	AnnoProcessorsExclude = "cainjekt.io/processors.exclude"

	FailPolicyOpen  = "fail-open"
	DefaultCAFile   = "/etc/cainjekt/ca-bundle.pem"
	DefaultMode     = "fs"
	WrapperPath     = "/cainjekt-entrypoint"
	HookContextFile = "/etc/cainjekt/hook-context.json"

	DefaultHookTimeoutSec = 2
)
