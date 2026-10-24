# One command gates everything: `make check`. Requires uv (https://docs.astral.sh/uv/).
UV ?= uv
RUN := $(UV) run --frozen
COV_MIN ?= 90

.PHONY: install fmt fmt-check lint typecheck test cov check demo bench clean

install:
	$(UV) sync --frozen

fmt:
	$(RUN) ruff format src tests scripts

fmt-check:
	$(RUN) ruff format --check src tests scripts

lint:
	$(RUN) ruff check src tests scripts

typecheck:
	$(RUN) mypy

test:
	$(RUN) pytest

cov:
	$(RUN) pytest --cov=controlmap --cov-branch --cov-report=term-missing --cov-fail-under=$(COV_MIN)

check: fmt-check lint typecheck cov

demo:
	$(RUN) python -u scripts/demo.py

bench:
	$(RUN) python -u scripts/bench.py

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov examples/acme/.controlmap
