CLUSTER_NAME ?= cainjekt-test-cluster
IMAGE_NAME ?= cainjekt
IMAGE_TAG ?= latest
IMAGE_REGISTRY ?= ghcr.io/tsuzu

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/cainjekt ./cmd/cainjekt

.PHONY: docker-build
docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	docker build --target=installer -t $(IMAGE_NAME)-installer:$(IMAGE_TAG) .

.PHONY: docker-push
docker-push: docker-build
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(IMAGE_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: kind-load
kind-load: docker-build prepare-test-cluster
	kind load docker-image $(IMAGE_NAME):$(IMAGE_TAG) --name $(CLUSTER_NAME)
	kind load docker-image $(IMAGE_NAME)-installer:$(IMAGE_TAG) --name $(CLUSTER_NAME)

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
	GOCACHE=/tmp/go-build-cache CAINJEKT_TLS_INTEGRATION=1 go test -tags=integration -count=1 -v ./integration -run TestKindIntegration

.PHONY: e2e-test
e2e-test: prepare-test-cluster
	GOCACHE=/tmp/go-build-cache CAINJEKT_E2E=1 go test -tags=integration -count=1 -v ./integration -run TestE2E

.PHONY: test-all
test-all: prepare-test-cluster
	GOCACHE=/tmp/go-build-cache CAINJEKT_TLS_INTEGRATION=1 CAINJEKT_E2E=1 go test -tags=integration -count=1 -v ./integration
