.PHONY: verify up down lint test

DOCKER := $(shell test -x /usr/local/bin/docker -a -e /Applications/Docker.app/Contents/Resources/bin/docker && echo yes || echo no)

verify:
	@echo "no tests yet"

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

lint:
	@echo "no lint yet"

test:
	@echo "no tests yet"
