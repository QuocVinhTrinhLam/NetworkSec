FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements.txt ./
RUN python -m pip install --prefix=/install -r requirements.txt

FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/usr/local/bin:$PATH

RUN addgroup --system --gid 10001 monitor \
    && adduser --system --uid 10001 --ingroup monitor --home /app monitor

WORKDIR /app
COPY --from=builder /install /usr/local
COPY --chown=monitor:monitor app ./app
COPY --chown=monitor:monitor config ./config
COPY --chown=monitor:monitor fixtures ./fixtures
RUN mkdir -p /app/data && chown monitor:monitor /app/data

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
