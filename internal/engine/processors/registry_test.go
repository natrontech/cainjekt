package processors

import "testing"

func TestByNameMatchesDefaultProcessors(t *testing.T) {
	t.Parallel()

	for _, p := range Default() {
		got, ok := ByName(p.Name())
		if !ok {
			t.Fatalf("ByName(%q) was not found", p.Name())
		}
		if got.Name() != p.Name() {
			t.Fatalf("ByName(%q) returned processor %q", p.Name(), got.Name())
		}
	}
}

func TestByNameNotFound(t *testing.T) {
	t.Parallel()

	if p, ok := ByName("unknown-processor"); ok || p != nil {
		t.Fatalf("ByName() should return not found for unknown name")
	}
}
