# Container image for the choochoo controller and web UI.
#
# No BLE / pylgbst extras — containers are for the hardwareless demo and
# for the broker-adjacent web UI in hardware mode. Any host driving a real
# train must run the controller bare-metal so it can reach the BLE stack.
#
# Build:
#   docker build -t choochoo:dev .
#
# Run (manual):
#   docker run --rm -p 8000:8000 -e CHOOCHOO_PROTOCOL=mqtt choochoo:dev web
#
# In practice you'd use `docker-compose.fake.yml` with --profile mqtt|modbus.

FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim

WORKDIR /app

# Resolve and install dependencies first, in their own layer, so source
# changes don't bust the dependency cache.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev

# Now copy source and install the project itself.
COPY src/ ./src/
RUN uv sync --frozen --no-dev

# Drop privileges. The project doesn't need root, and an attacker who pops
# a controller / web shell shouldn't immediately own the container too.
RUN useradd -m -u 1000 choochoo
USER choochoo

# `--no-sync` skips the per-invocation lockfile check; the venv is already
# good from the build step above.
ENTRYPOINT ["uv", "run", "--no-sync", "choochoo"]
