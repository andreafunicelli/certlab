# syntax=docker/dockerfile:1.7
# Shared image for API, Celery worker and Celery beat.
FROM python:3.12-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml ./
COPY app ./app
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --upgrade pip && /opt/venv/bin/pip install .

FROM python:3.12-slim-bookworm
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN groupadd --system --gid 10001 cdp && useradd --system --uid 10001 --gid cdp --home /app --shell /usr/sbin/nologin cdp \
 && mkdir -p /var/lib/cdp/artifacts && chown -R cdp:cdp /var/lib/cdp && chmod 0700 /var/lib/cdp/artifacts
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY --chown=cdp:cdp app ./app
COPY --chown=cdp:cdp alembic ./alembic
COPY --chown=cdp:cdp scripts ./scripts
COPY --chown=cdp:cdp alembic.ini ./
USER cdp
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/healthz',timeout=4).status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--timeout-graceful-shutdown", "30"]
