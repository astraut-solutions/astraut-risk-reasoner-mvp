.PHONY: install run lint format test

install:
	pip install -e ".[dev]"

run:
	astraut-risk demo

lint:
	ruff check src tests

format:
	black src tests
	ruff check --fix src tests

test:
	pytest
