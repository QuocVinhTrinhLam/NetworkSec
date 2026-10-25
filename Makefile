.PHONY: install test lint run mock compose-up compose-down

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

test:
	.venv/bin/pytest

lint:
	.venv/bin/ruff check app tests

run:
	.venv/bin/uvicorn app.main:app --reload

mock:
	.venv/bin/python -m app.mock_generator --count 18 --interval 0.2 --duplicate-every 4

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down
