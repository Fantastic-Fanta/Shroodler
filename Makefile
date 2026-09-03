.PHONY: verify up down lint test test-unit test-integration bootstrap bins desktop-test cover cli install-cli

ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
VENV := $(ROOT).venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
DOCKER := $(shell test -e /Applications/Docker.app/Contents/Resources/bin/docker && echo yes || echo no)

bootstrap:
	@test -x "$(PY)" || python3 -m venv "$(VENV)"
	@$(PIP) install -q -e "$(ROOT)packages/crawler-py[dev]" -e "$(ROOT)packages/cli"
	@$(VENV)/bin/playwright install chromium

bins:
	cd packages/crawler-go && go build -o shroodler-go ./cmd/shroodler
	cd packages/proxy-go && go build -o shroodler-proxy ./cmd/shroodler-proxy

cli: bootstrap bins
	@echo "Python CLI:  $(VENV)/bin/shroodler"
	@echo "Repo wrapper: $(ROOT)scripts/shroodler"
	@echo "Go CLI:      $(ROOT)packages/crawler-go/shroodler-go"
	@echo "Proxy:       $(ROOT)packages/proxy-go/shroodler-proxy"
	@$(VENV)/bin/shroodler version

install-cli: cli
	mkdir -p "$(HOME)/.local/bin"
	ln -sf "$(VENV)/bin/shroodler" "$(HOME)/.local/bin/shroodler"
	ln -sf "$(ROOT)packages/crawler-go/shroodler-go" "$(HOME)/.local/bin/shroodler-go"
	ln -sf "$(ROOT)packages/proxy-go/shroodler-proxy" "$(HOME)/.local/bin/shroodler-proxy"
	@echo "Symlinked into $(HOME)/.local/bin — add that directory to PATH if needed"

lint: bootstrap
	$(VENV)/bin/ruff check packages/crawler-py/shroodler packages/crawler-py/tests packages/cli
	cd packages/crawler-go && gofmt -l . | { ! grep .; }

desktop-test: bins
	cd packages/desktop-app && node --test tests/*.mjs
	cd packages/desktop-app/src-tauri && cargo test -q

test-unit: bootstrap bins
	cd packages/crawler-py && "$(ROOT).venv/bin/pytest" tests/unit -q
	cd packages/secret-patterns && "$(ROOT).venv/bin/pytest" tests -q
	cd packages/report-generator && "$(ROOT).venv/bin/pytest" tests -q
	cd packages/crawler-go && go test ./...
	cd packages/proxy-go && go test ./...
	cd packages/desktop-app && node --test tests/*.mjs
	cd packages/desktop-app/src-tauri && cargo test -q
	cd packages/payload-tester && PYTHONPATH="$(ROOT)packages/payload-tester" "$(ROOT).venv/bin/pytest" tests -q
	cd packages/cli && "$(ROOT).venv/bin/pytest" tests -q

cover: bootstrap
	cd packages/crawler-py && "$(ROOT).venv/bin/pytest" tests/unit --cov=shroodler --cov-fail-under=90 -q --cov-report=term
	cd packages/crawler-go && go test ./internal/... -coverpkg=./internal/...
	cd packages/proxy-go && go test ./internal/... -coverpkg=./internal/...

test-integration: bootstrap up
	cd packages/crawler-py && "$(ROOT).venv/bin/pytest" tests/integration -q
	cd packages/crawler-go && go test ./tests -count=1

test: test-unit test-integration

verify: lint test-unit
	$(MAKE) down
	$(MAKE) test-integration
	$(MAKE) down
	@echo "verify ok"

up:
ifeq ($(DOCKER),yes)
	docker compose up -d --build
else
	@echo "Docker not available; starting local target processes"
	bash scripts/local-up.sh
endif

down:
ifeq ($(DOCKER),yes)
	docker compose down --remove-orphans
else
	bash scripts/local-down.sh
endif
