FROM python:3.11-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

# Security: non-root user
RUN groupadd -r chakra && useradd -r -g chakra -d /app -s /sbin/nologin chakra

COPY --from=builder /install /usr/local
COPY src/ ./src/
COPY data/ ./data/

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Minimal attack surface: no shell, no sudo
USER chakra

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "chakra_gateway:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "4", "--log-level", "info", "--no-access-log"]