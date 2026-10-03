# syntax=docker/dockerfile:1

# ── Stage 1: build a self-contained virtualenv ───────────────────────────────
# (Pin the base image by digest in CI for fully reproducible builds.)
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
# Copy only the dependency manifest first so this layer is cached until requirements change.
COPY requirements.txt .
# BuildKit cache mount: wheels are reused across builds but never stored in an image layer.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt


# ── Stage 2: minimal runtime image, runs as an unprivileged user ─────────────
# Same base image as the builder, so the venv's python symlink stays valid.
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8000

# Fixed numeric UID/GID so Kubernetes `runAsNonRoot` checks can verify it.
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app main.py ./

USER 10001:10001
EXPOSE 8000

# slim images have no curl: probe with the Python we already ship.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:${PORT}/healthz', timeout=2)"

# `exec` makes uvicorn PID 1, so it receives SIGTERM and lets in-flight SSE streams drain
# (up to 20 s) during deploys. Scale out with replicas, or set WEB_CONCURRENCY for more
# worker processes per container. The app never writes to disk, so this also runs with:
#   docker run --read-only --cap-drop ALL --security-opt no-new-privileges ...
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT} --timeout-graceful-shutdown 20"]
