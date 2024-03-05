GO_MATRIX ?= darwin/amd64 darwin/arm64 \
  linux/amd64 linux/arm linux/arm64 \
  windows/amd64

APP_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_HASH ?= $(shell git show -s --format=%h)

GO_DEBUG_ARGS   ?= -v -ldflags "-X main.version=$(GO_APP_VERSION)+debug -X main.commit=$(GIT_HASH) -X main.date=$(APP_DATE) -X main.builtBy=makefiles"
GO_RELEASE_ARGS ?= -v -ldflags "-X main.version=$(GO_APP_VERSION) -X main.commit=$(GIT_HASH) -X main.date=$(APP_DATE) -X main.builtBy=makefiles -s -w"

GENERATED_FILES += artifacts/certs/ca.pem
GENERATED_FILES += artifacts/certs/server.pem
GENERATED_FILES += artifacts/certs/server-key.pem
GENERATED_FILES += artifacts/certs/client.pem
GENERATED_FILES += artifacts/certs/client-key.pem
GENERATED_FILES += artifacts/certs/cert.pem
GENERATED_FILES += artifacts/certs/key.pem

-include .makefiles/Makefile
-include .makefiles/pkg/go/v1/Makefile
-include .makefiles/ext/na4ma4/lib/golangci-lint/v1/Makefile
-include .makefiles/ext/na4ma4/lib/cfssl/v1/Makefile
-include .makefiles/ext/na4ma4/lib/goreleaser/v1/Makefile

.makefiles/ext/na4ma4/%: .makefiles/Makefile
	@curl -sfL https://raw.githubusercontent.com/na4ma4/makefiles-ext/main/v1/install | bash /dev/stdin "$@"

.makefiles/%:
	@curl -sfL https://makefiles.dev/v1 | bash /dev/stdin "$@"

.PHONY: run
run: artifacts/build/debug/$(GOHOSTOS)/$(GOHOSTARCH)/jwt-auth-proxy
	"$<" $(RUN_ARGS)

.PHONY: install
install: $(REQ) $(_SRC) | $(USE)
	$(eval PARTS := $(subst /, ,$*))
	$(eval BUILD := $(word 1,$(PARTS)))
	$(eval OS    := $(word 2,$(PARTS)))
	$(eval ARCH  := $(word 3,$(PARTS)))
	$(eval BIN   := $(word 4,$(PARTS)))
	$(eval ARGS  := $(if $(findstring debug,$(BUILD)),$(DEBUG_ARGS),$(RELEASE_ARGS)))

	CGO_ENABLED=$(CGO_ENABLED) GOOS="$(OS)" GOARCH="$(ARCH)" go install $(ARGS) "./cmd/..."


######################
# Docker Testing
######################

artifacts/dockertest/dev: artifacts/build/debug/linux/amd64/jwt-auth-proxy Dockerfile scripts/replace-links-in-ssl-certs.sh
	mkdir -p "$(@D)"
	mkdir -p "artifacts/dockertmp/scripts"
	cp "$(<)" "artifacts/dockertmp/"
	cp "Dockerfile" "artifacts/dockertmp/"
	cp scripts/replace-links-in-ssl-certs.sh artifacts/dockertmp/scripts/
	docker build -t ghcr.io/na4ma4/jwt-auth-proxy:dev -f Dockerfile artifacts/dockertmp | tee "$(@)"

.PHONY: docker-local
docker-local: artifacts/dockertest/dev

.PHONY: docker-test
docker-test: artifacts/dockertest/dev artifacts/certs/ca.pem
	docker run -ti --rm -p 8011:80/tcp -v "$(shell pwd)/artifacts/certs/ca.pem:/run/secrets/ca.pem" -e "BYPASS_AUTH_PATHS=/v2/" -e "LEGACY_USERS=test1:test2" -e "REMOVE_AUTH_HEADER=true" -e "BACKEND_URL=http://github.com" ghcr.io/na4ma4/jwt-auth-proxy:dev


######################
# Linting
######################

ci:: lint
