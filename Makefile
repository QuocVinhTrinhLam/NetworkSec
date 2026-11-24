.PHONY: install up up-notifications down logs seed scenario test test-syslog-integration test-processor-integration lint format build run compose-validate syslog-up syslog-generate syslog-replay benchmark-local benchmark-compose

NAME ?= ssh_bruteforce
DURATION ?= 60
BENCHMARK_DURATION ?= 10

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

up:
	docker compose up -d --build --wait

up-notifications:
	docker compose --profile notifications up -d --build --wait

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

seed:
	docker compose run --rm --no-deps mock python -m app.mock --seed-days 7 --rate 0

scenario:
	SCENARIO_NAME=$(NAME) SCENARIO_DURATION=$(DURATION) docker compose --profile mock run --rm mock

test:
	.venv/bin/pytest -m "not e2e and not syslog_integration and not storage_integration and not processor_integration" --cov=app --cov-report=term-missing

test-syslog-integration:
	RUN_SYSLOG_INTEGRATION=1 .venv/bin/pytest -m syslog_integration tests/integration

test-processor-integration:
	RUN_PROCESSOR_INTEGRATION=1 .venv/bin/pytest -m processor_integration tests/integration

lint:
	.venv/bin/ruff check app tests scripts
	.venv/bin/ruff format --check app tests scripts
	.venv/bin/mypy app

format:
	.venv/bin/ruff check --fix app tests scripts
	.venv/bin/ruff format app tests scripts

build:
	docker compose build

compose-validate:
	docker compose --file compose.yaml config --quiet

syslog-up:
	docker compose up -d --wait rsyslog

syslog-generate:
	docker compose --profile syslog-tools run --rm syslog-generator

syslog-replay:
	docker compose --profile syslog-tools run --rm syslog-generator python -m app.syslog_generator --protocol tcp --rate 50 --count 0 --loghub-file /app/fixtures/logs/cisco-ios.log

benchmark-local:
	.venv/bin/python -m app.benchmark --mode local --duration $(BENCHMARK_DURATION) --repetitions 1

benchmark-compose:
	.venv/bin/python -m app.benchmark --mode compose --duration $(BENCHMARK_DURATION) --repetitions 3

run:
	.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1
