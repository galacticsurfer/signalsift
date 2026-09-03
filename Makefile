.PHONY: sync test lint fmt health smoke

sync:
	uv sync

test:
	uv run pytest -q

lint:
	uv run ruff check src tests

fmt:
	uv run ruff format src tests
	uv run ruff check --fix src tests

health:
	uv run signalsift health

smoke:
	uv run python scripts/smoke_test.py
