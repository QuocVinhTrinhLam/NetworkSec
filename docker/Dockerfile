# syntax=docker/dockerfile:1

FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS dependencies

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN --mount=type=bind,source=requirements.txt,target=/build/requirements.txt,readonly \
    --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --no-compile -r requirements.txt

FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN addgroup --system --gid 10001 monitor \
    && adduser --system --uid 10001 --ingroup monitor --home /app monitor

WORKDIR /app
COPY --from=dependencies --link /opt/venv /opt/venv
COPY --link --chown=10001:10001 app ./app
COPY --link --chown=10001:10001 config ./config
COPY --link --chown=10001:10001 fixtures ./fixtures
COPY --link --chown=10001:10001 migrations ./migrations
RUN mkdir -p /app/data /app/processor-state \
    && chown 10001:10001 /app/data /app/processor-state

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
