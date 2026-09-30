FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
COPY . .
RUN uv sync --locked --no-dev

EXPOSE 80
CMD ["uv", "run", "fastapi", "run", "src/modulo_auth/main.py", "--host", "0.0.0.0", "--port", "80"]
