.PHONY: build run stop migrate test fmt

# Install/sync the uv workspace (all packages + dev deps).
build:
	uv sync

# Start the local Postgres + Apache AGE stack.
run:
	docker compose up -d

stop:
	docker compose down

# Apply pending database migrations (uses ADMIN_DATABASE_URL).
migrate:
	uv run python -m infra_twin.db.migrate

# Run the test suite against the local stack.
test:
	uv run pytest

# Serve the query API locally.
serve:
	uv run uvicorn infra_twin.api.app:create_app --factory --reload

# Install + run the web UI dev server (http://localhost:5173).
web-install:
	cd apps/web && npm install

web:
	cd apps/web && npm run dev

# Type-check and production-build the web UI.
web-build:
	cd apps/web && npm run build
