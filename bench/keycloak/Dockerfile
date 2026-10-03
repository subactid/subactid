# Keycloak for the sizing rig, built from the upstream GitHub release tarball (checksum pinned),
# so it works without access to quay.io. Unmodified.
#
# Local use only, never pushed. Runs in development mode with an in-memory database.

FROM mcr.microsoft.com/openjdk/jdk:25-ubuntu

ARG KEYCLOAK_VERSION=26.7.4
ARG KEYCLOAK_SHA256=04823c336b797a7e18889a44262a7a64e6bf624cbbcc518c85e2622176ff2eee

# Optional CA for networks with a TLS-intercepting proxy: `--secret id=build_ca,src=<pem>`.
RUN --mount=type=secret,id=build_ca,target=/tmp/build-ca.crt \
    set -eu; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    if [ -s /tmp/build-ca.crt ]; then \
      cp /tmp/build-ca.crt /usr/local/share/ca-certificates/build-proxy.crt; \
      update-ca-certificates; \
    fi; \
    curl -fsSL -o /tmp/keycloak.tar.gz \
      "https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz"; \
    echo "${KEYCLOAK_SHA256}  /tmp/keycloak.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/keycloak; \
    tar -xzf /tmp/keycloak.tar.gz -C /opt/keycloak --strip-components=1; \
    rm -f /tmp/keycloak.tar.gz; \
    mkdir -p /opt/keycloak/data/import; \
    groupadd -r keycloak; \
    useradd -r -g keycloak -d /opt/keycloak keycloak; \
    chown -R keycloak:keycloak /opt/keycloak; \
    rm -rf /var/lib/apt/lists/*

COPY subactid-bench-realm.json /opt/keycloak/data/import/subactid-bench-realm.json

# Since 26.6, development mode listens on localhost only unless it knows it is in a container,
# which the official image declares and a tarball build does not.
ENV KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=false \
    KC_HTTP_HOST=0.0.0.0

# The rig waits on this before measuring. Health is on the management port.
HEALTHCHECK --interval=5s --timeout=5s --retries=60 --start-period=30s \
  CMD curl -fsS http://127.0.0.1:9000/health/ready || exit 1

USER keycloak
EXPOSE 8080 9000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev", "--import-realm"]
