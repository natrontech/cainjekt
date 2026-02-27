CLUSTER_NAME ?= cainjekt-test-cluster

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/cainjekt ./cmd/cainjekt

.PHONY: prepare-test-cluster
prepare-test-cluster:
	# Create a kind cluster for testing if it doesn't already exist
	-kind get clusters | grep -q $(CLUSTER_NAME) || kind create cluster --name $(CLUSTER_NAME) --config ./hack/kind.yaml
	kind export kubeconfig --name $(CLUSTER_NAME)

.PHONY: reset-test-cluster
reset-test-cluster:
	-kind delete cluster --name $(CLUSTER_NAME)
	kind create cluster --name $(CLUSTER_NAME) --config ./hack/kind.yaml
	kind export kubeconfig --name $(CLUSTER_NAME)

.PHONY: copy-plugin
copy-plugin: build prepare-test-cluster
	docker cp ./bin/cainjekt $(shell kind get nodes --name=$(CLUSTER_NAME) | head -n 1):/cainjekt

.PHONY: exec-plugin
exec-plugin: copy-plugin
	docker exec -it $(shell kind get nodes --name=$(CLUSTER_NAME) | head -n 1) /cainjekt --idx 10

.PHONY: integration-test
integration-test:
	GOCACHE=/tmp/go-build-cache go test -tags=integration -count=1 -v ./integration
