package wrapper

import (
	"os"
	"testing"
)

func TestApplyContextEnvSetsValues(t *testing.T) {
	t.Setenv("CAINJEKT_TEST_ENV", "before")

	got, err := applyContextEnv([]string{"CAINJEKT_TEST_ENV=after"})
	if err != nil {
		t.Fatalf("applyContextEnv() error = %v", err)
	}
	if os.Getenv("CAINJEKT_TEST_ENV") != "after" {
		t.Fatalf("env value mismatch: got=%q want=%q", os.Getenv("CAINJEKT_TEST_ENV"), "after")
	}
	if len(got) == 0 {
		t.Fatalf("applyContextEnv() should return current environment")
	}
}

func TestApplyContextEnvSkipsInvalidEntry(t *testing.T) {
	t.Setenv("CAINJEKT_TEST_INVALID", "keep")

	if _, err := applyContextEnv([]string{"CAINJEKT_TEST_INVALID"}); err != nil {
		t.Fatalf("applyContextEnv() error = %v", err)
	}
	if os.Getenv("CAINJEKT_TEST_INVALID") != "keep" {
		t.Fatalf("invalid env entry should be ignored")
	}
}
