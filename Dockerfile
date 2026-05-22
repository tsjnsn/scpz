# OCI-compatible image for Docker and Podman.
# syntax=docker/dockerfile:1

FROM python:3.13-slim-bookworm AS builder

WORKDIR /build

RUN pip install --no-cache-dir build

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m build --wheel --outdir /dist

FROM python:3.13-slim-bookworm

WORKDIR /work

RUN useradd --create-home --uid 10001 --non-unique scpz

COPY --from=builder /dist/*.whl /tmp/

RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

USER scpz

ENTRYPOINT ["scpz"]

CMD ["--help"]
