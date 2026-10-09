.PHONY: build test vet docs ui mutants mutants-e2e e2e e2e-cluster e2e-down clean

build:
	go build -o bin/podpeers ./cmd/podpeers

test:
	go test -race ./...

vet:
	go vet ./... && go vet -tags e2e ./test/e2e/
	./hack/hygiene.sh
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

# Break each negative case's protection (hack/mutants/*.patch) and require
# the tests to fail for the right reason.
mutants:
	./hack/mutants.sh

mutants-e2e: e2e-cluster
	./hack/mutants.sh --e2e

# Renders every Mermaid diagram in the Markdown (needs node; set
# PUPPETEER_EXECUTABLE_PATH to a local Chrome to skip the browser download).
docs:
	./hack/check-docs.sh

# Drives the web UI in headless Chrome (needs node; see hack/check-ui.sh).
ui:
	./hack/check-ui.sh

# Creates (or reuses) the throwaway local k3d cluster, then runs the real-cluster
# suite against it. The cluster's kubeconfig lives in .e2e/ and is never merged
# into your default kubeconfig.
e2e: e2e-cluster
	@command -v helm >/dev/null || (echo "e2e needs helm"; exit 1)
	@command -v kwokctl >/dev/null || (echo "e2e needs kwokctl (go install sigs.k8s.io/kwok/cmd/kwokctl@v0.7.0)"; exit 1)
	PODPEERS_E2E_KUBECONFIG=$(CURDIR)/.e2e/kubeconfig PODPEERS_E2E_OUT=$(CURDIR)/.e2e/out \
		go test -tags e2e -count=1 -v -timeout 25m ./test/e2e/

e2e-cluster:
	./hack/e2e-cluster.sh up

e2e-down:
	./hack/e2e-cluster.sh down

clean:
	rm -rf bin .e2e/out
