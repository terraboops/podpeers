.PHONY: build test vet e2e e2e-cluster e2e-down clean

build:
	go build -o bin/podpeers ./cmd/podpeers

test:
	go test -race ./...

vet:
	go vet ./... && go vet -tags e2e ./test/e2e/
	./hack/hygiene.sh
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

# Creates (or reuses) the throwaway local k3d cluster, then runs the real-cluster
# suite against it. The cluster's kubeconfig lives in .e2e/ and is never merged
# into your default kubeconfig.
e2e: e2e-cluster
	@command -v helm >/dev/null || (echo "e2e needs helm"; exit 1)
	PODPEERS_E2E_KUBECONFIG=$(CURDIR)/.e2e/kubeconfig PODPEERS_E2E_OUT=$(CURDIR)/.e2e/out \
		go test -tags e2e -count=1 -v -timeout 25m ./test/e2e/

e2e-cluster:
	./hack/e2e-cluster.sh up

e2e-down:
	./hack/e2e-cluster.sh down

clean:
	rm -rf bin .e2e/out
