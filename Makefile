VERSION ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST    := dist
AGENT   := ./cmd/vims-gadget

.PHONY: test vet linux vectors clean

test:
	go test -race ./...

vet:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ."; exit 1; }
	go vet ./...

linux:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64         go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/vims-gadget-linux-arm64 $(AGENT)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm   GOARM=7 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/vims-gadget-linux-armv7 $(AGENT)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm   GOARM=6 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/vims-gadget-linux-armv6 $(AGENT)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64         go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/vims-gadget-linux-amd64 $(AGENT)
	cd $(DIST) && sha256sum vims-gadget-linux-* > SHA256SUMS

vectors:
	go test ./protocol -run TestVectors -update

clean:
	rm -rf $(DIST)
