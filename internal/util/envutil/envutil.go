// Package envutil provides helpers for manipulating environment variable slices.
package envutil

import "strings"

// Upsert sets or updates an environment variable in the given env slice.
func Upsert(env []string, key, value string) []string {
	prefix := key + "="
	entry := prefix + value
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = entry
			return env
		}
	}
	return append(env, entry)
}
