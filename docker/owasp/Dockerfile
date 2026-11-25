# --------------------------------------------------
# Stage 1: Fetch and verify security tools (Trivy, Conftest, OPA)
# --------------------------------------------------
FROM registry.redhat.io/ubi9/ubi-minimal:latest AS tools

ARG TRIVY_VERSION=0.76.2
ARG TRIVY_SHA256=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
ARG CONFTEST_VERSION=0.71.1
ARG CONFTEST_SHA256=c3f6b2a753bd56e377a1e51a95ae3e057f926f2e9139f7d5b5dfbbaf810f7985
ARG OPA_VERSION=1.22.4
ARG OPA_SHA256=35e3b352e715e80624ead6c89930d8585f6f7d94cdc409eb2a9fe36620dcccba

RUN microdnf install -y --nodocs curl tar gzip \
    && microdnf clean all

WORKDIR /tmp/tools

# Each artifact is verified against a pinned SHA-256 before it is installed.
RUN curl -fsSL -o trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && echo "${TRIVY_SHA256}  trivy.tar.gz" | sha256sum -c - \
    && tar -xzf trivy.tar.gz -C /usr/local/bin trivy

RUN curl -fsSL -o conftest.tar.gz \
      "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" \
    && echo "${CONFTEST_SHA256}  conftest.tar.gz" | sha256sum -c - \
    && tar -xzf conftest.tar.gz -C /usr/local/bin conftest

RUN curl -fsSL -o /usr/local/bin/opa \
      "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" \
    && echo "${OPA_SHA256}  /usr/local/bin/opa" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/opa /usr/local/bin/trivy /usr/local/bin/conftest

# --------------------------------------------------
# Stage 2: Minimal runtime image (non-root)
# --------------------------------------------------
FROM registry.redhat.io/ubi9/python-312-minimal:latest

LABEL org.opencontainers.image.title="OWASP Security Gates" \
      org.opencontainers.image.description="SBOM, OWASP Top 10, OPA policy enforcement pipeline" \
      org.opencontainers.image.vendor="Security Engineering" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

USER root
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=tools /usr/local/bin/conftest /usr/local/bin/conftest
COPY --from=tools /usr/local/bin/opa /usr/local/bin/opa

# Create non-root user with a fixed UID
RUN useradd -m -u 10001 security \
    && mkdir -p /app \
    && chown -R security:root /app

WORKDIR /app

# Python dependencies (pinned in scripts/requirements.txt)
COPY scripts/requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt \
    && rm requirements.txt

COPY --chown=security:root scripts/ scripts/
COPY --chown=security:root policy/ policy/
COPY --chown=security:root exceptions/ exceptions/

USER 10001

ENTRYPOINT ["python3", "scripts/owasp_analyzer.py"]
