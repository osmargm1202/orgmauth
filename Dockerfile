FROM python:3.11-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev cargo rust

COPY pyproject.toml uv.lock ./
RUN pip install uv && uv sync --no-dev

FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache libpq

COPY --from=builder /app/.venv /app/.venv
COPY app /app/app

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

EXPOSE 8500

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8500"]
