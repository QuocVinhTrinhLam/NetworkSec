.PHONY: install up down logs seed scenario test lint build run

NAME ?= ssh_bruteforce
DURATION ?= 60

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

up:
	docker compose up -d --build dashboard bot

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

seed:
	docker compose run --rm --no-deps mock python -m app.mock --seed-days 7 --rate 0

scenario:
	SCENARIO_NAME=$(NAME) SCENARIO_DURATION=$(DURATION) docker compose --profile mock run --rm mock

test:
	.venv/bin/pytest --cov=app --cov-report=term-missing

lint:
	.venv/bin/ruff check app tests
	.venv/bin/mypy app

build:
	docker compose build

run:
	.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1
