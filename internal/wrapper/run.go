package wrapper

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/tsuzu/cainjekt/internal/config"
)

func Run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("wrapper requires original command in argv[1:]")
	}
	trustStore := strings.TrimSpace(os.Getenv(config.EnvWrapperTrustStore))
	env := os.Environ()
	if trustStore != "" {
		env = setDefault(env, "SSL_CERT_FILE", trustStore)
		env = setDefault(env, "NODE_EXTRA_CA_CERTS", trustStore)
		env = setDefault(env, "REQUESTS_CA_BUNDLE", trustStore)
	}

	argv0 := os.Args[1]
	if !strings.ContainsRune(argv0, '/') {
		resolved, err := exec.LookPath(argv0)
		if err != nil {
			return fmt.Errorf("failed to resolve command %q: %w", argv0, err)
		}
		argv0 = resolved
	}

	if err := syscall.Exec(argv0, os.Args[1:], env); err != nil {
		return fmt.Errorf("exec failed: %w", err)
	}
	return nil
}

func setDefault(env []string, key, value string) []string {
	prefix := key + "="
	for _, v := range env {
		if strings.HasPrefix(v, prefix) {
			return env
		}
	}
	return append(env, prefix+value)
}
