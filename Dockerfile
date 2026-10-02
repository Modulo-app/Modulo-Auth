FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN uv sync --locked --no-dev

EXPOSE 50051
CMD ["uv", "run", "--no-sync", "modulo-auth"]
