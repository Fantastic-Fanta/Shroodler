.PHONY: verify up down lint test test-unit test-integration bootstrap

ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
VENV := $(ROOT).venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
DOCKER := $(shell test -e /Applications/Docker.app/Contents/Resources/bin/docker && echo yes || echo no)

bootstrap:
	@test -x "$(PY)" || python3 -m venv "$(VENV)"
	@$(PIP) install -q -e "$(ROOT)packages/crawler-py[dev]"
	@$(VENV)/bin/playwright install chromium

lint: bootstrap
	$(VENV)/bin/ruff check packages/crawler-py/shroodler packages/crawler-py/tests

test-unit: bootstrap
	cd packages/crawler-py && "$(ROOT).venv/bin/pytest" tests/unit -q
	cd packages/secret-patterns && "$(ROOT).venv/bin/pytest" tests -q
	cd packages/report-generator && "$(ROOT).venv/bin/pytest" tests -q

test-integration: bootstrap up
	cd packages/crawler-py && "$(ROOT).venv/bin/pytest" tests/integration -q

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
