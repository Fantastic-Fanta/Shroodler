.PHONY: verify up down lint test

verify:
	@echo "no tests yet"

up:
	docker compose up -d --build

down:
	docker compose down --remove-orphans

lint:
	@echo "no lint yet"

test:
	@echo "no tests yet"
