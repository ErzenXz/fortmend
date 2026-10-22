GO ?= go
ZIG ?= zig

.PHONY: build test fmt check fx-build fx-test cross clean

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/fortmend ./cmd/fortmend

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...
	cd third_party/fx && $(ZIG) fmt src/

check:
	$(GO) vet ./...
	$(GO) test ./...
	cd third_party/fx && $(ZIG) fmt --check src/

fx-build:
	cd third_party/fx && $(ZIG) build -Doptimize=ReleaseSafe
	cp third_party/fx/zig-out/bin/fx bin/fortmend-fx

fx-test:
	cd third_party/fx && $(ZIG) build test

cross:
	./scripts/build-release.sh

clean:
	rm -rf bin dist
