# Makefile — common dev / ops shortcuts. Pure conveniences; everything
# below has a documented "what this actually runs" so users on
# non-make systems can just copy the command.

.PHONY: help install dev test lint demo-2-peers doctor reset-state \
        smoke-searxng image clean

help:  ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:  ## One-line operator install (pipx install swf-node).
	@bash scripts/install.sh

dev:  ## Set up an editable dev environment (uv if available, else venv).
	@bash scripts/dev.sh

test:  ## Run the default test marker filter.
	pytest -q -m 'not searxng_live and not slow and not integration'

lint:  ## Run ruff (read-only).
	ruff check src/ tests/

demo-2-peers:  ## Spin up two peers locally; tail logs.
	@bash scripts/demo-2-peers.sh

doctor:  ## swf-node doctor + swf-peer health.
	@bash scripts/doctor.sh

reset-state:  ## Remove identity / state / knowledge dirs (with prompts).
	@bash scripts/reset-state.sh

smoke-searxng:  ## Start the test SearXNG fixture and probe /healthz.
	@bash scripts/smoke-searxng.sh

image:  ## Build the docker image (multi-arch via buildx is in CI).
	docker build -t swf-node:dev .

clean:  ## Remove build artefacts.
	rm -rf build dist *.egg-info src/*.egg-info .pytest_cache .coverage htmlcov coverage.xml
